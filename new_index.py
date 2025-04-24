#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import logging
import sys
import urllib3
from requests import Session

# --- Disable SSL warnings (self‑signed certs) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("create_index.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- Configuration ---
SYCOPE_HOST = ""    # adres Sycope z protokołem i portem
LOGIN       = "admin"                        # użytkownik Sycope
PASSWORD    = ""               # hasło Sycope
INDEX_NAME  = "suricata"               # nazwa tworzonego indeksu

# Ścieżka bazowa do API
API_BASE    = "/npm/api/v1"

# --- Definicja pól Suricata ---
FIELDS = [
    {"name":"timestamp",           "type":"long",     "description":"Event timestamp",         "displayName":"Timestamp"},
    {"name":"flow_id",             "type":"long",     "description":"Suricata flow ID",         "displayName":"Flow ID"},
    {"name":"in_iface",            "type":"string",               "description":"Interface name",          "displayName":"Interface"},
    {"name":"event_type",          "type":"string",               "description":"Type of event",           "displayName":"Event Type"},
    {"name":"src_ip",              "type":"ip4",      "description":"Source IP address",       "displayName":"Src IP"},
    {"name":"src_port",            "type":"int",      "description":"Source port",             "displayName":"Src Port"},
    {"name":"dest_ip",             "type":"ip4",      "description":"Destination IP address",  "displayName":"Dest IP"},
    {"name":"dest_port",           "type":"int",      "description":"Destination port",        "displayName":"Dest Port"},
    {"name":"proto",               "type":"string",               "description":"Layer 4 protocol",        "displayName":"Protocol"},
    # alert fields
    {"name":"alert_action",        "type":"string",               "description":"Alert action",            "displayName":"Alert Action"},
    {"name":"alert_gid",           "type":"int",      "description":"Generator ID",            "displayName":"Alert GID"},
    {"name":"alert_signature_id",  "type":"int",      "description":"Signature ID",            "displayName":"Sig ID"},
    {"name":"alert_rev",           "type":"int",      "description":"Signature revision",      "displayName":"Sig Rev"},
    {"name":"alert_signature",     "type":"string",               "description":"Signature text",          "displayName":"Signature"},
    {"name":"alert_category",      "type":"string",               "description":"Signature category",      "displayName":"Category"},
    {"name":"alert_severity",      "type":"int",      "description":"Severity level",          "displayName":"Severity"},
    # anomaly fields
    {"name":"anomaly_type",        "type":"string",               "description":"Anomaly type",           "displayName":"Anomaly Type"},
    {"name":"anomaly_event",       "type":"string",               "description":"Anomaly event",          "displayName":"Anomaly Event"},
    {"name":"anomaly_layer",       "type":"string",               "description":"Anomaly layer",          "displayName":"Layer"},
    # additional
    {"name":"app_proto",           "type":"string",               "description":"Application protocol",    "displayName":"App Proto"}
]

def main():
    # 1. Utwórz sesję
    session = Session()
    session.verify = False
    session.headers.update({"Content-Type": "application/json"})

    # 2. Logowanie
    login_payload = {"username": LOGIN, "password": PASSWORD}
    login_url = f"{SYCOPE_HOST}{API_BASE}/login"
    r = session.post(login_url, json=login_payload)
    if r.status_code != 200:
        logging.error(f"Logowanie nie powiodło się: {r.status_code} {r.text}")
        sys.exit(1)
    logging.info("Zalogowano do Sycope API")

    # 3. Pobranie CSRF tokenu z ciasteczka (jeśli wymagane)
    csrf = session.cookies.get("XSRF-TOKEN")
    if csrf:
        session.headers.update({"X-XSRF-TOKEN": csrf})

    # 4. Przygotuj payload do tworzenia indeksu
    payload = {
        "category": "userIndex.index",
        "config": {
            "name":       INDEX_NAME,
            "active":     True,
            "rotation":   "daily",
            "storeRaw":   True,
            "fields":     FIELDS
        }
    }

    # 5. Wyślij żądanie tworzenia indeksu
    create_url = f"{SYCOPE_HOST}{API_BASE}/config-element-index/user-index"
    r = session.post(create_url, json=payload)
    if r.status_code in (200, 201):
        logging.info(f"Indeks '{INDEX_NAME}' został pomyślnie utworzony.")
        print(json.dumps(r.json(), indent=2))
    else:
        logging.error(f"Błąd tworzenia indeksu: {r.status_code}")
        try:
            print(r.json())
        except ValueError:
            print(r.text)

    # 6. (Opcjonalnie) Wyloguj się
    session.get(f"{SYCOPE_HOST}{API_BASE}/logout")
    logging.info("Sesja zakończona")

if __name__ == "__main__":
    main()
