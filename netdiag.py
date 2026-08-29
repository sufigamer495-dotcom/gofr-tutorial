#!/usr/bin/env python3
"""
NetDiag - Network & Infrastructure Diagnostics CLI Tool
Author: Network Admin Utilities

Features:
1. Wi-Fi Signal & Channel Analyzer (`netdiag wifi`)
   - Scans nearby Wi-Fi networks (SSID, BSSID, Signal %, RSSI, Channel, Security).
   - Provides channel usage & interference analysis.
2. Subnet & IP Asset Mapper (`netdiag subnet`)
   - Performs multi-threaded IP sweep, hostname resolution, and local ARP MAC mapping.
3. Service Port & SSL Monitor (`netdiag ssl-ports`)
   - Port scanner with TLS/SSL certificate status monitoring (expiration, issuer, validity).
"""

import sys
import os
import argparse
import socket
import ssl
import subprocess
import platform
import re
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


# Helper for output formatting (Windows CMD & standard terminal)
def print_table(headers, rows):
    if not rows:
        print("No results found.")
        return
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    header_line = " | ".join(f"{str(h):<{col_widths[i]}}" for i, h in enumerate(headers))
    separator = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(separator)
    for row in rows:
        print(" | ".join(f"{str(val):<{col_widths[i]}}" for i, val in enumerate(row)))


# ==========================================
# 1. Wi-Fi Signal & Channel Analyzer
# ==========================================

def parse_netsh_output(output_text):
    """
    Parses Windows `netsh wlan show networks mode=bssid` output.
    Returns list of dicts with network details.
    """
    networks = []
    current_ssid = None
    current_auth = ""
    current_cipher = ""

    lines = output_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        ssid_match = re.match(r"^SSID\s+\d+\s+:\s*(.*)$", line, re.IGNORECASE)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
            if not current_ssid:
                current_ssid = "<Hidden SSID>"
            i += 1
            continue

        auth_match = re.match(r"^Authentication\s+:\s*(.*)$", line, re.IGNORECASE)
        if auth_match:
            current_auth = auth_match.group(1).strip()
            i += 1
            continue

        cipher_match = re.match(r"^Encryption\s+:\s*(.*)$", line, re.IGNORECASE)
        if cipher_match:
            current_cipher = cipher_match.group(1).strip()
            i += 1
            continue

        bssid_match = re.match(r"^BSSID\s+\d+\s+:\s*(.*)$", line, re.IGNORECASE)
        if bssid_match:
            bssid = bssid_match.group(1).strip()
            signal = 0
            channel = 0

            # Read next lines for signal and channel
            j = i + 1
            while j < len(lines):
                sub_line = lines[j].strip()
                if sub_line.startswith("BSSID") or sub_line.startswith("SSID"):
                    break
                sig_match = re.match(r"^Signal\s+:\s*(\d+)%", sub_line, re.IGNORECASE)
                if sig_match:
                    signal = int(sig_match.group(1))
                chan_match = re.match(r"^Channel\s+:\s*(\d+)", sub_line, re.IGNORECASE)
                if chan_match:
                    channel = int(chan_match.group(1))
                j += 1

            # Estimate RSSI in dBm from Signal % (approximate standard formula: RSSI = (Signal / 2) - 100)
            rssi = (signal / 2) - 100 if signal > 0 else -100

            networks.append({
                "ssid": current_ssid or "<Unknown>",
                "bssid": bssid,
                "signal_percent": signal,
                "rssi_dbm": int(rssi),
                "channel": channel,
                "authentication": current_auth,
                "encryption": current_cipher
            })
            i = j
            continue

        i += 1
    return networks


def parse_nmcli_output(output_text):
    """
    Parses Linux `nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi` output.
    """
    networks = []
    lines = output_text.strip().splitlines()
    if not lines:
        return networks

    # Skip header line if present
    start_idx = 1 if "SSID" in lines[0] or "BSSID" in lines[0] else 0
    for line in lines[start_idx:]:
        parts = line.split()
        if len(parts) >= 5:
            ssid = parts[0]
            bssid = parts[1]
            try:
                chan = int(parts[2])
                sig = int(parts[3])
            except ValueError:
                continue
            sec = " ".join(parts[4:])
            rssi = (sig / 2) - 100
            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal_percent": sig,
                "rssi_dbm": int(rssi),
                "channel": chan,
                "authentication": sec,
                "encryption": sec
            })
    return networks


def analyze_channel_interference(networks):
    """
    Calculates channel usage frequencies and identifies congested channels.
    """
    channel_counts = {}
    for net in networks:
        ch = net.get("channel", 0)
        if ch > 0:
            channel_counts[ch] = channel_counts.get(ch, 0) + 1
    return channel_counts


def scan_wifi(as_json=False):
    system = platform.system()
    networks = []

    if system == "Windows":
        try:
            cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            networks = parse_netsh_output(res.stdout)
        except Exception as e:
            if not as_json:
                print(f"[!] Error running netsh: {e}")
    elif system == "Linux":
        try:
            cmd = ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = res.stdout.strip().splitlines()
            for line in lines:
                fields = line.split(":")
                if len(fields) >= 5:
                    ssid, bssid, chan, sig, sec = fields[0], fields[1], fields[2], fields[3], fields[4]
                    try:
                        c_num = int(chan)
                        s_num = int(sig)
                    except ValueError:
                        continue
                    networks.append({
                        "ssid": ssid or "<Hidden>",
                        "bssid": bssid,
                        "signal_percent": s_num,
                        "rssi_dbm": int((s_num / 2) - 100),
                        "channel": c_num,
                        "authentication": sec,
                        "encryption": sec
                    })
        except Exception:
            # Fallback to standard nmcli or empty
            pass

    interference = analyze_channel_interference(networks)

    if as_json:
        result = {
            "platform": system,
            "total_networks": len(networks),
            "channel_usage": interference,
            "networks": networks
        }
        print(json.dumps(result, indent=2))
        return

    print("=========================================================")
    print("                Wi-Fi Signal & Channel Analyzer          ")
    print("=========================================================\n")
    if not networks:
        print("[!] No Wi-Fi networks found or Wi-Fi adapter unavailable.")
        print("    Ensure wireless interface is enabled and running with proper permissions.")
        return

    headers = ["SSID", "BSSID", "Signal %", "RSSI (dBm)", "Channel", "Security"]
    rows = []
    for net in sorted(networks, key=lambda x: x["signal_percent"], reverse=True):
        rows.append([
            net["ssid"],
            net["bssid"],
            f"{net['signal_percent']}%",
            f"{net['rssi_dbm']} dBm",
            net["channel"],
            net["authentication"]
        ])

    print_table(headers, rows)
    print("\n--- Channel Interference & Distribution ---")
    sorted_chans = sorted(interference.items(), key=lambda x: x[0])
    for ch, count in sorted_chans:
        bar = "█" * count
        print(f"Channel {ch:2d} : {count:2d} APs {bar}")


# ==========================================
# 2. Subnet & IP Asset Mapper
# ==========================================

def get_mac_address_table():
    """
    Parses local ARP table (Windows `arp -a` or Linux `arp -n`).
    Returns dict mapping IP -> MAC address.
    """
    arp_table = {}
    system = platform.system()
    cmd = ["arp", "-a"] if system == "Windows" else ["arp", "-n"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            # Matches IP and MAC pattern
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", line)
            if ip_match and mac_match:
                arp_table[ip_match.group(1)] = mac_match.group(1).upper().replace("-", ":")
    except Exception:
        pass
    return arp_table


def expand_target_ip_range(target_str):
    """
    Expands CIDR (e.g. 192.168.1.0/24), IP range (e.g. 192.168.1.1-192.168.1.50),
    or single IP into a list of IP string targets.
    """
    target_str = target_str.strip()
    # Range notation e.g., 192.168.1.1-192.168.1.50 or 192.168.1.1-50
    if "-" in target_str:
        parts = target_str.split("-")
        start_ip_str = parts[0].strip()
        end_part = parts[1].strip()

        start_ip = ipaddress.IPv4Address(start_ip_str)
        if "." in end_part:
            end_ip = ipaddress.IPv4Address(end_part)
        else:
            # e.g., 192.168.1.1-50
            start_octets = start_ip_str.split(".")
            start_octets[-1] = end_part
            end_ip = ipaddress.IPv4Address(".".join(start_octets))

        start_int = int(start_ip)
        end_int = int(end_ip)
        if start_int > end_int:
            start_int, end_int = end_int, start_int
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]

    # CIDR or Single IP
    try:
        net = ipaddress.ip_network(target_str, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target_str]


def ping_or_probe_host(ip, timeout=1.0, check_ports=None):
    """
    Attempts ICMP ping / TCP probe to check if host is online.
    Returns dict if online, else None.
    """
    is_up = False
    system = platform.system()

    # 1. Standard Ping
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout + 0.5)
        if res.returncode == 0:
            is_up = True
    except Exception:
        pass

    # 2. Fast TCP Socket Fallback if ping fails or is blocked
    open_ports = []
    ports_to_check = check_ports if check_ports else [80, 443, 22, 445, 139, 8080]

    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout / 2.0)
        try:
            res = sock.connect_ex((ip, port))
            if res == 0:
                is_up = True
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()

    if not is_up:
        return None

    # Reverse DNS Lookup
    hostname = "N/A"
    try:
        dns_res = socket.gethostbyaddr(ip)
        hostname = dns_res[0]
    except Exception:
        pass

    return {
        "ip": ip,
        "status": "Online",
        "hostname": hostname,
        "open_ports": open_ports
    }


def scan_subnet(target_range, threads=50, timeout=1.0, check_ports=None, as_json=False):
    ip_list = expand_target_ip_range(target_range)
    if not as_json:
        print(f"[*] Scanning subnet/range: {target_range} ({len(ip_list)} host addresses)...")
        print(f"[*] Using {threads} threads with {timeout}s timeout...")
        print("---------------------------------------------------------")

    mac_table = get_mac_address_table()
    active_hosts = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {executor.submit(ping_or_probe_host, ip, timeout, check_ports): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            res = future.result()
            if res:
                res["mac"] = mac_table.get(res["ip"], "Unknown / Off-Link")
                active_hosts.append(res)

    active_hosts.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))

    if as_json:
        result = {
            "target_range": target_range,
            "scanned_count": len(ip_list),
            "online_count": len(active_hosts),
            "hosts": active_hosts
        }
        print(json.dumps(result, indent=2))
        return

    headers = ["IP Address", "Status", "Hostname", "MAC Address", "Open Ports (Sampled)"]
    rows = []
    for host in active_hosts:
        ports_str = ", ".join(map(str, host["open_ports"])) if host["open_ports"] else "None detected"
        rows.append([host["ip"], host["status"], host["hostname"], host["mac"], ports_str])

    print_table(headers, rows)
    print(f"\n[+] Scan Complete: Found {len(active_hosts)} active host(s) out of {len(ip_list)} total scanned.")


# ==========================================
# 3. Service Port & SSL Monitor
# ==========================================

DEFAULT_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443
]

def inspect_ssl_certificate(host, port=443, timeout=3.0):
    """
    Connects via TLS/SSL to extract certificate validity, issuer, and expiration date.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Fetch cert even if self-signed for diagnostic inspection

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Der binary fallback if getpeercert returned empty dict due to CERT_NONE
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        return {"has_ssl": False, "error": "No certificate returned"}
                    # Re-handshake with validation context to parse cert dict if needed
                    return {"has_ssl": True, "issuer": "Peer Certificate Present (Unparsed DER)", "valid_until": "N/A", "days_remaining": "N/A", "status": "UNKNOWN"}

                # Format subject & issuer
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))

                cn = subject_dict.get("commonName", host)
                issuer_cn = issuer_dict.get("commonName") or issuer_dict.get("organizationName", "Unknown Issuer")

                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")

                days_left = None
                status = "VALID"
                exp_date_fmt = "N/A"

                if not_after_str:
                    # Python ssl date format: 'MMM DD HH:MM:SS YYYY GMT'
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    exp_date_fmt = exp_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                    now = datetime.now(timezone.utc)
                    days_left = (exp_date - now).days

                    if days_left < 0:
                        status = "EXPIRED"
                    elif days_left <= 30:
                        status = "EXPIRING SOON"

                return {
                    "has_ssl": True,
                    "common_name": cn,
                    "issuer": issuer_cn,
                    "valid_from": not_before_str,
                    "valid_until": exp_date_fmt,
                    "days_remaining": days_left,
                    "status": status,
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                }
    except Exception as e:
        return {"has_ssl": False, "error": str(e)}


def check_single_port(host, port, timeout=1.5, check_ssl=True):
    """
    Checks if TCP port is open and evaluates SSL/TLS certificate if present.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    open_status = False
    try:
        res = sock.connect_ex((host, port))
        if res == 0:
            open_status = True
    except Exception:
        pass
    finally:
        sock.close()

    if not open_status:
        return {"port": port, "state": "Closed / Filtered", "ssl_info": None}

    ssl_info = None
    if check_ssl and port in [443, 8443, 465, 993, 995, 587]:
        ssl_info = inspect_ssl_certificate(host, port, timeout=timeout)
    elif check_ssl:
        # Attempt quick SSL handshake to check if port supports TLS
        ssl_info = inspect_ssl_certificate(host, port, timeout=timeout)
        if ssl_info and not ssl_info.get("has_ssl"):
            ssl_info = None

    return {
        "port": port,
        "state": "Open",
        "ssl_info": ssl_info
    }


def scan_ports_and_ssl(host, ports=None, threads=20, timeout=1.5, check_ssl=True, as_json=False):
    target_ports = ports if ports else DEFAULT_COMMON_PORTS

    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"[!] Unable to resolve target host '{host}': {e}")
        return

    if not as_json:
        print(f"[*] Scanning host: {host} ({target_ip}) across {len(target_ports)} port(s)...")
        print("---------------------------------------------------------")

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(check_single_port, target_ip, p, timeout, check_ssl): p for p in target_ports}
        for future in as_completed(future_to_port):
            results.append(future.result())

    results.sort(key=lambda x: x["port"])

    if as_json:
        out = {
            "target_host": host,
            "target_ip": target_ip,
            "scanned_ports_count": len(target_ports),
            "results": results
        }
        print(json.dumps(out, indent=2))
        return

    headers = ["Port", "State", "SSL/TLS", "Issuer", "Cert Expiration", "Days Left", "Status"]
    rows = []
    for item in results:
        port_num = item["port"]
        state = item["state"]
        ssl_data = item.get("ssl_info")

        if state == "Open":
            if ssl_data and ssl_data.get("has_ssl"):
                tls_ver = ssl_data.get("tls_version", "TLS")
                issuer = ssl_data.get("issuer", "Unknown")
                until = ssl_data.get("valid_until", "N/A")
                days = str(ssl_data.get("days_remaining", "N/A"))
                status = ssl_data.get("status", "VALID")
                rows.append([port_num, state, tls_ver, issuer, until, days, status])
            else:
                rows.append([port_num, state, "No / Non-TLS", "-", "-", "-", "-"])
        else:
            rows.append([port_num, state, "-", "-", "-", "-", "-"])

    print_table(headers, rows)


# ==========================================
# CLI Argument Parser Setup
# ==========================================

def main():
    parser = argparse.ArgumentParser(
        description="NetDiag - Network & Infrastructure Diagnostics Utility for Windows CMD & Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Diagnostic subcommands")

    # 1. Wi-Fi subcommand
    wifi_parser = subparsers.add_parser("wifi", help="Scan nearby Wi-Fi networks, signal strength, and channel usage.")
    wifi_parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    # 2. Subnet subcommand
    subnet_parser = subparsers.add_parser("subnet", help="Perform IP range / subnet discovery & MAC mapping.")
    subnet_parser.add_argument("target", help="Target CIDR range (e.g. 192.168.1.0/24) or IP range (e.g. 192.168.1.1-192.168.1.50).")
    subnet_parser.add_argument("--threads", type=int, default=50, help="Number of concurrent worker threads (default: 50).")
    subnet_parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds for host ping/probe (default: 1.0).")
    subnet_parser.add_argument("--ports", type=int, nargs="+", help="Custom ports to check during host discovery probe.")
    subnet_parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    # 3. SSL & Port Monitor subcommand
    ssl_parser = subparsers.add_parser("ssl-ports", help="Scan target ports and inspect SSL/TLS certificate status.")
    ssl_parser.add_argument("host", help="Target hostname or IP address (e.g. example.com or 192.168.1.1).")
    ssl_parser.add_argument("--ports", type=int, nargs="+", help="List of specific ports to scan (e.g. --ports 80 443 8443).")
    ssl_parser.add_argument("--threads", type=int, default=20, help="Number of concurrent worker threads (default: 20).")
    ssl_parser.add_argument("--timeout", type=float, default=1.5, help="Timeout in seconds for socket connection (default: 1.5).")
    ssl_parser.add_argument("--no-ssl", action="store_true", help="Disable SSL certificate inspection.")
    ssl_parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    if args.command == "wifi":
        scan_wifi(as_json=args.json)
    elif args.command == "subnet":
        scan_subnet(args.target, threads=args.threads, timeout=args.timeout, check_ports=args.ports, as_json=args.json)
    elif args.command == "ssl-ports":
        scan_ports_and_ssl(args.host, ports=args.ports, threads=args.threads, timeout=args.timeout, check_ssl=not args.no_ssl, as_json=args.json)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
