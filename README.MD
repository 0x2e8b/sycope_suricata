# Suricata Integration with Sycope

This integration enables sending Suricata security events to a custom index in **Sycope** for further correlation, search, and visualization.

Supported event types: **alerts**, **anomalies**, **DNS**, **HTTP**, **TLS**, and **file info**.

---

##  Components

The integration consists of three components:

1. **Sycope** – Receives data through the REST API.
2. **Suricata** – Generates JSON-based security events in `eve.json` format.
3. **Integration Script** – A Python-based injector that parses logs and sends them to Sycope.

>  **You can run the script on the same host as Suricata**, but **do not run it on the Sycope appliance** – due to permission and isolation limitations.

---


##  How the Integration Works

The `eve_processor.py` script:

- Reads Suricata logs from `eve.json`
- Filters for configured event types (`alert`, `anomaly`, `dns`, `http`, `tls`, `fileinfo`)
- Applies optional whitelists/blacklists per event type
- Transforms each event into a row matching the field structure of a predefined **custom index** in Sycope
- Sends rows via Sycope REST API
- Maintains a `last_timestamp.txt` file to avoid duplicate processing

---

##  Repository Contents

```
.
├── dashboards/
│   ├── Suricata_Dashboard_Sycope.json   # Overview dashboard (KPIs + trends + top talkers)
│   ├── Suricata_Alert_Analysis.json     # Alert deep-dive (severity, categories, conversations)
│   ├── Suricata_Protocols.json          # DNS, HTTP, TLS protocol analysis
│   └── Suricata_File_Analysis.json      # File transfer analysis (hashes, types, protocols)
├── examples/
│   ├── suricata.yaml.nodpi-example      # Minimal config (alerts + anomalies only)
│   └── suricata.yaml.full-example       # Full config (alerts + anomalies + DNS + HTTP + TLS + files)
├── config.json                          # Configuration file
├── eve_processor.py                     # Main processing script
├── install.py                           # Creates a new Sycope index with proper fields (43 columns)
├── uninstall.py                         # Optional cleanup for custom indexes
├── requirements.txt                     # Python dependencies
```

---

##  Requirements

- Python 3.8+
- Suricata 6.0+
- Sycope >= 3.1 with API access
- `requests` module:
  ```bash
  pip3 install requests
  ```

---

##  User & Role Setup in Sycope

After creating new index, add a dedicated user and role in Sycope for log ingestion:

1. **Create a Role**  
   Go to **Configuration → Roles**, create a role (e.g., `SuricataInject`) with:
   - Permission to inject data only into custom indexes

2. **Create a User**  
   Go to **Configuration → Users**, create a user (e.g., `suricata_ingestor`) and assign the above role.

---

##  Configuration (`config.json`)

```jsonc
{
  // URL of the Sycope API endpoint (HTTPS strongly recommended)
  "sycope_host": "https://<sycope-ip>",

  // Sycope API user (must have rights to inject data into custom indexes)
  "sycope_login": "suricata_ingestor",

  // Password for the above API user
  "sycope_pass": "your_password",

  // Name of the custom index defined in Sycope
  "index_name": "suricata",

  // Path to the Suricata eve.json log file
  "suricata_eve_json_path": "/var/log/suricata/eve.json",

  // File to track the timestamp of the last processed event
  "last_timestamp_file": "last_timestamp.txt",

  // List of event types to process
  // Supported: "alert", "anomaly", "dns", "http", "tls", "fileinfo"
  "event_types": ["alert", "anomaly", "dns", "http", "tls", "fileinfo"],

  // Whitelist/blacklist per event type (empty = no filtering)
  // Whitelist takes priority: if non-empty, only listed items are processed
  "anomaly_whitelist": [],
  "anomaly_blacklist": [],
  "alert_whitelist": [],
  "alert_blacklist": [],
  "dns_whitelist": [],
  "dns_blacklist": [],
  "http_whitelist": [],
  "http_blacklist": [],
  "tls_whitelist": [],
  "tls_blacklist": [],
  "fileinfo_whitelist": [],
  "fileinfo_blacklist": []
}
```

>  JSON does not support comments natively — this format is shown for documentation purposes only. Use a standard `config.json` file without comments in production.

---

##  Script Usage

| Script               | Purpose                                    | Example                                        |
|----------------------|--------------------------------------------|------------------------------------------------|
| **install.py**       | Create index & mappings                    | `python3 install.py`                           |
| **eve_processor.py** | Parse & inject new events                  | `python3 eve_processor.py` (e.g., via systemd) |

---

##  Running the Script

Run manually:
```bash
python3 eve_processor.py
```
Or run as a service (recommended)

---

##  Running as a System Service

For automated processing, set up a systemd service with a 30-second timer:

### 1. Create Service File
Create `/etc/systemd/system/suricata-eve-processor.service`:
```ini
[Unit]
Description=Suricata EVE Log Processor
After=network.target

[Service]
Type=oneshot
User=suricata
Group=suricata
WorkingDirectory=/opt/suricata-integration
ExecStart=/usr/bin/python3 /opt/suricata-integration/eve_processor.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2. Create Timer File
Create `/etc/systemd/system/suricata-eve-processor.timer`:
```ini
[Unit]
Description=Run Suricata EVE Processor every 30 seconds
Requires=suricata-eve-processor.service

[Timer]
OnBootSec=30sec
OnUnitActiveSec=30sec
AccuracySec=1sec

[Install]
WantedBy=timers.target
```
> **Note**: Adjust time, default timer is set for 30 seconds

### 3. Enable and Start
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable and start the timer
sudo systemctl enable suricata-eve-processor.timer
sudo systemctl start suricata-eve-processor.timer

# Check status
sudo systemctl status suricata-eve-processor.timer
```

### 4. Monitor Logs
```bash
# View service logs
sudo journalctl -u suricata-eve-processor.service -f

# View timer logs
sudo journalctl -u suricata-eve-processor.timer -f
```

>  **Note**: Adjust the `WorkingDirectory` and script path to match your installation location. The service runs under the `suricata` user for security isolation.

---

##  Notes

- The script requires a valid custom index in Sycope with matching column definitions.
- Running the script on the Sycope appliance is not supported due to security isolation.
- Supports filtering of unwanted events via whitelists or blacklists.
- Each index in Sycope has a **retention period**. Set it in **Settings → Indices → Retention** according to your storage policy.

---

##  Dashboard Import

1. In Sycope UI, go to **Dashboards → Import**
2. Upload all four dashboard JSON files from the `dashboards/` folder
3. Link them to the `suricata` index

### Dashboards Included

| Dashboard | Focus | Widgets |
|-----------|-------|---------|
| **Suricata Overview** | High-level security posture | 8 KPIs + event timeline + severity/type charts + top IPs/signatures |
| **Suricata Alert Analysis** | Alert deep-dive | Severity KPIs + category trends + protocol breakdown + alert detail table + conversation pairs |
| **Suricata Protocols** | DNS/HTTP/TLS analysis | Per-protocol timelines, top domains/hosts/SNIs, record types/status codes/TLS versions |
| **Suricata File Analysis** | File transfer analysis | File KPIs + timeline by protocol + file type distribution + top hashes/names + detail tables |

> **Note**: The Protocols and File Analysis dashboards require their respective event types enabled in both `config.json` and `suricata.yaml`. See `examples/suricata.yaml.full-example`.

---

## Notice

This integration **does not install or configure Suricata for you**.

You must install, configure, and run Suricata **independently**, including:
- System installation (e.g., `apt install suricata`)
- Enabling `eve.json` output
- Running Suricata as a system service

The provided Python scripts are intended **only for integrating** Suricata logs with **Sycope** using its REST API.

> Think of this as a log shipping and parsing layer, not a full IDS/IPS setup.


##  Suricata Setup

1. Install Suricata:
```bash
apt-get install suricata
```

2. Configure EVE JSON output in `/etc/suricata/suricata.yaml`.

   **Minimal setup** (alerts + anomalies only):
   ```yaml
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: /var/log/suricata/eve.json
         types:
           - alert:
               enabled: yes
               metadata: yes
           - anomaly:
               enabled: yes
   ```

   **Full setup** (alerts + anomalies + DNS + HTTP + TLS + file info):
   ```yaml
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: /var/log/suricata/eve.json
         types:
           - alert:
               enabled: yes
               metadata: yes
           - anomaly:
               enabled: yes
           - dns:
               enabled: yes
           - http:
               enabled: yes
               extended: yes
           - tls:
               enabled: yes
               extended: yes
           - files:
               enabled: yes
               force-magic: yes
               force-hash: [sha256]
   ```

   > See `examples/suricata.yaml.full-example` for a complete configuration file.

   Make sure Suricata logs to the path defined in `config.json`.

---

##  Troubleshooting

- Check log: `eve_processor.log` or `journalctl -u suricata_eve_processor`
- Make sure the Sycope user has proper API rights
- Confirm `eve.json` contains supported event types (`alert`, `anomaly`, `dns`, `http`, `tls`, `fileinfo`)
- If the Protocols dashboard shows no data, verify DNS/HTTP/TLS logging is enabled in `suricata.yaml`
- If the File Analysis dashboard shows no data, verify `files` logging is enabled in `suricata.yaml` with `force-magic: yes` and `force-hash: [sha256]`
- Feel free to contact our engineers via dedicated Discord Channel: https://discord.gg/dFjTv854
