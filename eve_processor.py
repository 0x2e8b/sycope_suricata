#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import logging
import socket
from datetime import datetime, timezone
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# — Wyłącz warningi SSL dla self‑signed certs —
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# — Logowanie —
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("eve_processor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

CONFIG_FILE = 'config.json'
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))

def load_config(path):
    try:
        cfg = json.load(open(path))
        logging.info(f"Wczytano konfigurację z {path}")
        for key in ("anomaly_whitelist","alert_whitelist",
                    "anomaly_blacklist","alert_blacklist"):
            lst = cfg.get(key); cfg[f"{key}_set"] = set(lst) if isinstance(lst, list) else set()
        return cfg
    except Exception as e:
        logging.error(f"BŁĄD wczytywania config: {e}")
        sys.exit(1)

def load_last_ts(path):
    if not os.path.exists(path):
        return datetime.fromtimestamp(0, tz=timezone.utc)
    txt = open(path).read().strip()
    return datetime.fromisoformat(txt) if txt else datetime.fromtimestamp(0, tz=timezone.utc)

def save_last_ts(path, dt):
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    open(path, 'w').write(dt.isoformat())

def parse_eve_ts(s):
    if len(s)>6 and s[-3]==':': s = s[:-3]+s[-2:]
    dt = datetime.fromisoformat(s)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def should_process(ev, cfg, last_dt):
    et, ts = ev.get("event_type"), ev.get("timestamp")
    if not et or not ts:
        return False, None
    dt = parse_eve_ts(ts)
    if dt <= last_dt or et not in cfg["event_types"]:
        return False, dt
    if et=="alert":
        sid = ev.get("alert",{}).get("signature_id")
        if sid is None or (cfg["alert_whitelist"] and sid not in cfg["alert_whitelist_set"]) \
           or (not cfg["alert_whitelist"] and sid in cfg["alert_blacklist_set"]):
            return False, dt
    if et=="anomaly":
        name = ev.get("anomaly",{}).get("event")
        if name is None or (cfg["anomaly_whitelist"] and name not in cfg["anomaly_whitelist_set"]) \
           or (not cfg["anomaly_whitelist"] and name in cfg["anomaly_blacklist_set"]):
            return False, dt
    return True, dt

def build_row(ev, columns):
    row = []
    for col in columns:
        # jeśli pole jest bezpośrednio w ev
        if col in ev:
            val = ev[col]
        else:
            # próbujemy rozbić np. "alert_signature" → ["alert","signature"]
            parts = col.split('_', 1)
            if len(parts) == 2 and parts[0] in ev and isinstance(ev[parts[0]], dict):
                val = ev[parts[0]].get(parts[1])
            else:
                val = None
        # konwersja timestamp na ms
        if col == "timestamp" and isinstance(val, str):
            dt = parse_eve_ts(val)
            val = int(dt.timestamp() * 1000) if dt else None

        row.append(val)
    return row

def valid_ipv4(addr):
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        return False

def init_sycope(cfg):
    host = cfg["sycope_host"].rstrip("/")
    sess = requests.Session(); sess.verify=False
    sess.headers.update({"Content-Type":"application/json"})
    r = sess.post(f"{host}/npm/api/v1/login",
                  json={"username":cfg["sycope_login"],"password":cfg["sycope_pass"]})
    if r.status_code!=200:
        logging.error(f"Login failed: {r.status_code} {r.text}")
        sys.exit(1)
    token = sess.cookies.get("XSRF-TOKEN")
    if token: sess.headers.update({"X-XSRF-TOKEN":token})
    return sess, host

def main():
    cfg       = load_config(os.path.join(SCRIPT_DIR, CONFIG_FILE))
    eve_path  = cfg["suricata_eve_json_path"]
    ts_path   = os.path.join(SCRIPT_DIR, cfg["last_timestamp_file"])
    last_dt   = load_last_ts(ts_path)
    max_dt    = last_dt
    rows      = []
    counts    = {"processed":0, "skipped":0, "invalid":0}

    sess, host = init_sycope(cfg)

    # pobierz indeks
    r = sess.get(f"{host}/npm/api/v1/config-elements",
                 params={'filter':'category="userIndex.index"'})
    data = r.json().get("data",[])
    if not data:
        logging.error("Brak zdefiniowanych custom indeksów w Sycope.")
        sys.exit(1)
    idx         = data[0]
    INDEX_NAME  = idx["config"]["name"]
    fields      = idx["config"]["fields"]
    COLUMNS     = [f["name"] for f in fields]
    TYPES       = [f["type"] for f in fields]
    logging.info(f"Używam indeksu '{INDEX_NAME}', kolumny: {COLUMNS}")

    # parsuj eve.json
    with open(eve_path) as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                counts["skipped"]+=1
                continue

            ok, dt = should_process(ev, cfg, last_dt)
            if dt and dt>max_dt: max_dt=dt
            if not ok:
                counts["skipped"]+=1
                continue

            row = build_row(ev, COLUMNS)

            # walidacja ip4
            bad = False
            for val, typ in zip(row, TYPES):
                if typ=="ip4" and val is not None and not valid_ipv4(val):
                    bad = True; break
            if bad:
                counts["invalid"]+=1
                continue

            rows.append(row)
            counts["processed"]+=1

    logging.info(f"Procesed={counts['processed']} Skipped={counts['skipped']} InvalidIP={counts['invalid']}")

    if rows:
        payload = {
            "columns":       COLUMNS,
            "indexName":     INDEX_NAME,
            "sortTimestamp": True,
            "rows":          rows
        }
        inj = sess.post(f"{host}/npm/api/v1/index/inject", json=payload)
        logging.info(f"Inject status: {inj.status_code} {inj.text}")
    else:
        logging.info("Brak poprawnych wierszy do wstrzyknięcia.")

    if max_dt>last_dt:
        save_last_ts(ts_path, max_dt)
        logging.info(f"Zapisano nowy timestamp: {max_dt.isoformat()}")

    sess.get(f"{host}/npm/api/v1/logout")
    logging.info("Koniec działania")

if __name__=="__main__":
    main()
