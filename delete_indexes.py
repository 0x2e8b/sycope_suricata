#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# — Wyłącz warningi SSL dla self-signed certs —
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# — Logging —
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# — Załaduj config.json —
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
cfg = json.load(open(os.path.join(SCRIPT_DIR, "config.json")))

HOST     = cfg["sycope_host"].rstrip("/")
LOGIN    = cfg["sycope_login"]
PASSWORD = cfg["sycope_pass"]
API_BASE = "/npm/api/v1"

def main():
    session = requests.Session()
    session.verify = False
    session.headers.update({"Content-Type": "application/json"})

    # 1. Login
    r = session.post(f"{HOST}{API_BASE}/login",
                     json={"username": LOGIN, "password": PASSWORD})
    if r.status_code != 200:
        logging.error(f"Logowanie nie powiodło się: {r.status_code}")
        sys.exit(1)
    logging.info("Zalogowano do Sycope API")

    # CSRF
    csrf = session.cookies.get("XSRF-TOKEN")
    if csrf:
        session.headers.update({"X-XSRF-TOKEN": csrf})

    # 2. Pobierz wszystkie custom indeksy
    r = session.get(f"{HOST}{API_BASE}/config-elements",
                    params={"filter": 'category="userIndex.index"'})
    data = r.json().get("data", [])
    if not data:
        logging.info("Brak customowych indeksów do usunięcia.")
    else:
        for elem in data:
            idx_id = elem["id"]
            # 3. Usuń każdy
            del_url = f"{HOST}{API_BASE}/config-element-index/user-index/{idx_id}"
            dr = session.delete(del_url)
            if dr.status_code in (200, 204):
                logging.info(f"Usunięto indeks {idx_id}")
            else:
                logging.error(f"Nie udało się usunąć {idx_id}: {dr.status_code} {dr.text}")

    # 4. Logout
    session.get(f"{HOST}{API_BASE}/logout")
    logging.info("Wylogowano")

if __name__ == "__main__":
    main()
