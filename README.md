# NetDiag & NetAnalyzer - Network Diagnostics & Packet Analyzer Suite

`netdiag` and `netanalyzer` form a complete, ethical, cross-platform diagnostic and network traffic analysis toolkit. Designed for IT system administrators, network engineers, and security analysts, it runs seamlessly on **Windows Command Prompt (CMD)**, **PowerShell**, and **Linux** terminals.

---

## Suite Components

### 1. `netdiag.py` (Command-Line Network & Infrastructure Diagnostics)
* **Wi-Fi Signal & Channel Analyzer (`netdiag wifi`)**: Scans nearby authorized Wi-Fi access points, reporting SSID, BSSID, Signal %, RSSI (dBm), Channel, and Encryption with channel interference distribution.
* **Subnet & IP Asset Mapper (`netdiag subnet`)**: Fast multi-threaded IP sweep (CIDR or range), reverse DNS hostname resolution, and system ARP table MAC address mapping.
* **Service Port & SSL Monitor (`netdiag ssl-ports`)**: Scans TCP ports and performs TLS/SSL certificate status inspection (issuer, expiration date, days remaining, validity status).

### 2. `netanalyzer_gui.py` (Graphical Network Packet Analyzer & DPI Tool)
* **Interface & Packet Capture**: Records live network traffic across available interfaces (Ethernet, Wi-Fi, Loopback).
* **Deep Packet Inspection (DPI)**: Dissects protocol headers and payloads (Ethernet II, IPv4, IPv6, ARP, ICMP, TCP, UDP, and HTTP).
* **Advanced Filtering Engine**: Filter live or captured traffic using protocol names (`tcp`, `udp`, `http`), key-value pairs (`ip==192.168.1.1`, `port==80`), or payload keywords.
* **Conversations & Endpoint Statistics**: Aggregates live traffic metrics, protocol distribution percentages, and top conversation pairs.
* **Colorized Packet Display & Hex Viewer**: Protocol-highlighted treeview table with collapsible packet header tree inspector and Hex/ASCII byte pane.
* **Object Exporter**: Extract unencrypted file and stream payloads directly from HTTP/TCP protocol streams.

---

## Installation & Requirements

* **Python**: 3.8+ installed and accessible via command line (`python` or `python3`).
* **GUI Requirements**: Standard Tkinter library (included with official Python distributions on Windows and macOS; install `python3-tk` on Linux if needed).
* **Dependencies**: Uses standard Python library modules (`socket`, `ssl`, `subprocess`, `argparse`, `concurrent.futures`, `struct`, `tkinter`). No third-party pip packages required.

---

## Running NetDiag CLI Tools in Windows Command Prompt (CMD)

### 1. Wi-Fi Signal Scan & Channel Interference
```cmd
python netdiag.py wifi
```
*Output in JSON format:*
```cmd
python netdiag.py wifi --json
```

### 2. Subnet & Host Asset Mapper
Scan a local subnet CIDR (e.g., `192.168.1.0/24`):
```cmd
python netdiag.py subnet 192.168.1.0/24
```
Scan a custom IP range with 100 threads:
```cmd
python netdiag.py subnet 192.168.1.1-192.168.1.50 --threads 100
```

### 3. Service Port & SSL/TLS Certificate Monitor
Scan common ports on a domain or server:
```cmd
python netdiag.py ssl-ports example.com
```
Scan specific target ports on an IP address:
```cmd
python netdiag.py ssl-ports 192.168.1.1 --ports 80 443 8443 22
```

---

## Running Graphical NetAnalyzer GUI

Launch the GUI packet analyzer:
```cmd
python netanalyzer_gui.py
```

* **Start Capture**: Click `▶ Start Capture` to start capturing packets.
* **Filter Packets**: Type filters such as `http`, `tcp`, `ip==192.168.1.50`, or `example.com` into the filter box and press `Enter` or click `Apply Filter`.
* **View Statistics**: Click `📊 Statistics` to view protocol distribution and top conversation pairs.
* **Export Objects**: Click `📦 Export Objects` to view and save unencrypted files/payloads from captured streams.

---

## Running Automated Unit Test Suites

To run the complete test suite:

```cmd
python -m unittest test_netdiag.py test_netanalyzer.py
```
