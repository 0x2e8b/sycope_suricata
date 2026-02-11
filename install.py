#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Create custom index for Suricata security events in Sycope.

This script creates a custom index in Sycope for storing Suricata security events.
It connects to the Sycope API and sets up the necessary database schema with
predefined fields for Suricata EVE JSON log data.

The installer creates an index with fields for:
- Common network event data (IPs, ports, protocols, timestamps)
- Alert-specific fields (signature ID, severity, action, etc.)
- Anomaly-specific fields (event type, category)
- DNS, HTTP, and TLS protocol fields
- File info fields (filename, hashes, magic type, state)
- Client/server role determination fields

Script version: 2.0
Tested on Sycope 3.1
"""

import logging
import os
import sys

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

# Configuration file path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Suricata field definitions for the custom index
# These fields map to the data structure of Suricata EVE JSON logs
FIELDS = [
    # Common network event fields
    {"name": "timestamp", "type": "long", "description": "Event timestamp", "displayName": "Timestamp"},
    {"name": "flow_id", "type": "long", "description": "Suricata flow ID", "displayName": "Flow ID"},
    {"name": "in_iface", "type": "string", "description": "Interface name", "displayName": "Interface"},
    {"name": "event_type", "type": "string", "description": "Type of event", "displayName": "Event Type"},
    {"name": "src_ip", "type": "ip4", "description": "Source IP address", "displayName": "Source IP"},
    {"name": "src_port", "type": "int", "description": "Source port", "displayName": "Source Port"},
    {
        "name": "dest_ip",
        "type": "ip4",
        "description": "Destination IP address",
        "displayName": "Destination IP",
    },
    {
        "name": "dest_port",
        "type": "int",
        "description": "Destination port",
        "displayName": "Destination Port",
    },
    {
        "name": "clientIp",
        "type": "ip4",
        "description": "Client IP address (determined by port)",
        "displayName": "Client IP",
    },
    {
        "name": "clientPort",
        "type": "int",
        "description": "Client port (higher port number)",
        "displayName": "Client Port",
    },
    {
        "name": "serverIp",
        "type": "ip4",
        "description": "Server IP address (determined by port)",
        "displayName": "Server IP",
    },
    {
        "name": "serverPort",
        "type": "int",
        "description": "Server port (lower port number)",
        "displayName": "Server Port",
    },
    {"name": "proto", "type": "string", "description": "Layer 4 protocol", "displayName": "Protocol"},
    # Alert-specific fields (from Suricata alert events)
    {
        "name": "alert_action",
        "type": "string",
        "description": "Alert action",
        "displayName": "Suricata Alert Action",
    },
    {"name": "alert_gid", "type": "int", "description": "Generator ID", "displayName": "Suricata Alert GID"},
    {"name": "alert_signature_id", "type": "int", "description": "Signature ID", "displayName": "Sig ID"},
    {"name": "alert_rev", "type": "int", "description": "Signature revision", "displayName": "Sig Rev"},
    {
        "name": "event_signature",
        "type": "string",
        "description": "Signature text",
        "displayName": "Signature",
    },
    {
        "name": "event_category",
        "type": "string",
        "description": "Signature category",
        "displayName": "Category",
    },
    {"name": "alert_severity", "type": "int", "description": "Severity level", "displayName": "Severity"},
    # Additional protocol information
    {
        "name": "app_proto",
        "type": "string",
        "description": "Application protocol",
        "displayName": "App Proto",
    },
    # DNS fields (from dns event type)
    {"name": "dns_type", "type": "string", "description": "DNS query or answer", "displayName": "DNS Type"},
    {"name": "dns_rrname", "type": "string", "description": "DNS queried name", "displayName": "DNS Name"},
    {"name": "dns_rrtype", "type": "string", "description": "DNS record type", "displayName": "DNS Record Type"},
    {"name": "dns_rcode", "type": "string", "description": "DNS response code", "displayName": "DNS Response Code"},
    {"name": "dns_rdata", "type": "string", "description": "DNS answer data", "displayName": "DNS Answer"},
    {"name": "dns_id", "type": "int", "description": "DNS transaction ID", "displayName": "DNS ID"},
    # HTTP fields (from http event type)
    {
        "name": "http_hostname",
        "type": "string",
        "description": "HTTP hostname",
        "displayName": "HTTP Host",
    },
    {"name": "http_url", "type": "string", "description": "HTTP URL path", "displayName": "HTTP URL"},
    {"name": "http_method", "type": "string", "description": "HTTP method", "displayName": "HTTP Method"},
    {
        "name": "http_status",
        "type": "int",
        "description": "HTTP response status code",
        "displayName": "HTTP Status",
    },
    {
        "name": "http_user_agent",
        "type": "string",
        "description": "HTTP user agent",
        "displayName": "HTTP User Agent",
    },
    {
        "name": "http_content_type",
        "type": "string",
        "description": "HTTP content type",
        "displayName": "HTTP Content Type",
    },
    {"name": "http_length", "type": "long", "description": "HTTP content length", "displayName": "HTTP Length"},
    # TLS fields (from tls event type)
    {
        "name": "tls_subject",
        "type": "string",
        "description": "TLS certificate subject",
        "displayName": "TLS Subject",
    },
    {
        "name": "tls_issuer",
        "type": "string",
        "description": "TLS certificate issuer",
        "displayName": "TLS Issuer",
    },
    {"name": "tls_sni", "type": "string", "description": "TLS SNI hostname", "displayName": "TLS SNI"},
    {
        "name": "tls_version",
        "type": "string",
        "description": "TLS protocol version",
        "displayName": "TLS Version",
    },
    {"name": "tls_ja3", "type": "string", "description": "JA3 client fingerprint", "displayName": "JA3"},
    {"name": "tls_ja3s", "type": "string", "description": "JA3S server fingerprint", "displayName": "JA3S"},
    {
        "name": "tls_fingerprint",
        "type": "string",
        "description": "Certificate fingerprint",
        "displayName": "TLS Fingerprint",
    },
    # File info fields (from fileinfo event type)
    {"name": "file_name", "type": "string", "description": "Name of the file", "displayName": "File Name"},
    {"name": "file_size", "type": "long", "description": "File size in bytes", "displayName": "File Size"},
    {"name": "file_md5", "type": "string", "description": "MD5 hash of file", "displayName": "File MD5"},
    {"name": "file_sha1", "type": "string", "description": "SHA1 hash of file", "displayName": "File SHA1"},
    {
        "name": "file_sha256",
        "type": "string",
        "description": "SHA256 hash of file",
        "displayName": "File SHA256",
    },
    {
        "name": "file_magic",
        "type": "string",
        "description": "File type from magic bytes",
        "displayName": "File Type (Magic)",
    },
    {
        "name": "file_state",
        "type": "string",
        "description": "File transaction state",
        "displayName": "File State",
    },
    {
        "name": "file_stored",
        "type": "string",
        "description": "Whether file was stored to disk",
        "displayName": "File Stored",
    },
]


def main() -> None:
    """Create the Suricata custom index."""
    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=["sycope_host", "sycope_login", "sycope_pass", "index_name"],
        )
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("install.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("install.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Suricata Install script starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug("=" * 60)

    # Log field definitions
    logger.debug(f"Index field definitions ({len(FIELDS)} fields):")
    for field in FIELDS:
        logger.debug(f"  {field['name']}: type={field['type']}, displayName={field.get('displayName')}")

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Index name: {cfg['index_name']}")
    logger.debug(f"  API base: {cfg.get('api_base', '/npm/api/v1/')}")

    logging.info(f"Loaded configuration from {CONFIG_FILE}")

    # Connect to Sycope and create index
    logger.debug("Creating HTTP session...")
    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        logger.debug("Session headers set")

        try:
            logger.debug("Authenticating to Sycope API...")
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            logger.debug("Sycope authentication successful")

            logging.info(f"Creating Suricata index: {cfg['index_name']}")
            logger.debug("Index parameters:")
            logger.debug(f"  Name: {cfg['index_name']}")
            logger.debug("  Rotation: daily")
            logger.debug(f"  Fields count: {len(FIELDS)}")

            api.create_index(cfg["index_name"], FIELDS, rotation="daily")
            logging.info("Index created successfully")
            logger.debug("Index creation complete")

        except SycopeError as e:
            logging.error(f"Sycope API error: {e}")
            logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
            if hasattr(e, "status_code"):
                logger.debug(f"  Status code: {e.status_code}")
            if hasattr(e, "response"):
                logger.debug(f"  Response: {e.response}")
            sys.exit(1)
        finally:
            logger.debug("Logging out from Sycope...")
            api.log_out()
            logger.debug("Script complete")


if __name__ == "__main__":
    main()
