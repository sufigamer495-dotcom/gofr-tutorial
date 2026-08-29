# NetDiag - Network & Infrastructure Diagnostics Utility

`netdiag` is an ethical, cross-platform diagnostic CLI tool designed for IT system administrators, network engineers, and developers. It runs seamlessly on **Windows Command Prompt (CMD)**, **PowerShell**, and **Linux** terminals.

---

## Features

### 1. Wi-Fi Signal & Channel Analyzer (`netdiag wifi`)
* Scans nearby authorized Wi-Fi access points.
* Extracts SSID, BSSID, Signal Percentage (%), estimated RSSI (dBm), Channel, and Encryption/Authentication security protocol.
* Generates channel interference distribution charts to optimize router placement and select non-overlapping channels (e.g., 1, 6, 11).

### 2. Subnet & IP Asset Mapper (`netdiag subnet`)
* Performs fast multi-threaded IP range discovery (CIDR notation or start-end range).
* Resolves hostnames via reverse DNS lookup.
* Maps IP addresses to MAC addresses via system ARP tables for local asset management.
* Displays open ports detected during active discovery.

### 3. Service Port & SSL Monitor (`netdiag ssl-ports`)
* Scans specified or common network service TCP ports.
* Inspects TLS/SSL certificate status on secure services (HTTPS, SMTPS, IMAPS, etc.).
* Reports certificate issuer, subject CN, expiration timestamp, days remaining, and status warnings (`VALID`, `EXPIRING SOON`, `EXPIRED`).

---

## Installation & Requirements

* **Python**: 3.8+ installed and accessible via command line (`python` or `python3`).
* **Dependencies**: Uses standard Python library modules (`socket`, `ssl`, `subprocess`, `argparse`, `concurrent.futures`, `ipaddress`). No external pip dependencies required.

---

## Running in Windows Command Prompt (CMD)

### 1. Wi-Fi Signal Scan & Channel Interference
```cmd
python netdiag.py wifi
```
*Output in JSON format:*
```cmd
python netdiag.py wifi --json
```

### 2. Subnet & Host Asset Mapper
Scan a local subnet CIDR (e.g. `192.168.1.0/24`):
```cmd
python netdiag.py subnet 192.168.1.0/24
```
Scan a custom IP range with 100 threads:
```cmd
python netdiag.py subnet 192.168.1.1-192.168.1.50 --threads 100
```

### 3. Service Port & SSL/TLS Certificate Monitor
Scan common ports on a domain/server:
```cmd
python netdiag.py ssl-ports example.com
```
Scan specific target ports on an IP address:
```cmd
python netdiag.py ssl-ports 192.168.1.1 --ports 80 443 8443 22
```

---

## Running Unit Tests

To run the automated test suite:

```cmd
python -m unittest test_netdiag.py
```
