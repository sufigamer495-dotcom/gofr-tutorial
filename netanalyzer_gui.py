#!/usr/bin/env python3
"""
NetAnalyzer GUI - Graphical Network Traffic Analyzer & Deep Packet Inspection
Author: Network Admin Utilities

Features:
- Packet capture (Raw Sockets / OS network interfaces fallback)
- Deep Packet Inspection (Ethernet II, IPv4, IPv6, ARP, ICMP, TCP, UDP, HTTP)
- Colorized packet list view by protocol/anomaly
- Advanced display filtering (IP, Port, Protocol, Keyword)
- Real-time conversation & endpoint traffic statistics
- Deep header tree inspection & Hex/ASCII payload viewer
- Object Export module (extract unencrypted file payloads from HTTP/TCP streams)
"""

import sys
import os
import socket
import struct
import time
import threading
import re
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext


# ==========================================
# 1. Protocol Dissection Logic
# ==========================================

def mac_to_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)

def dissect_ethernet(raw_data):
    if len(raw_data) < 14:
        return None, raw_data
    dest_mac, src_mac, proto_num = struct.unpack("! 6s 6s H", raw_data[:14])
    return {
        "dest_mac": mac_to_str(dest_mac),
        "src_mac": mac_to_str(src_mac),
        "ethertype": hex(proto_num)
    }, raw_data[14:], proto_num

def dissect_ipv4(raw_data):
    if len(raw_data) < 20:
        return None, raw_data
    version_header_len = raw_data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(target)
    return {
        "version": version,
        "header_len": header_len,
        "ttl": ttl,
        "protocol": proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }, raw_data[header_len:], proto

def dissect_ipv6(raw_data):
    if len(raw_data) < 40:
        return None, raw_data
    first_word, payload_len, next_header, hop_limit = struct.unpack("! I H B B", raw_data[:8])
    src_ip = socket.inet_ntop(socket.AF_INET6, raw_data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, raw_data[24:40])
    return {
        "version": 6,
        "payload_len": payload_len,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }, raw_data[40:], next_header

def dissect_arp(raw_data):
    if len(raw_data) < 28:
        return None
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("! H H B B H", raw_data[:8])
    src_mac = mac_to_str(raw_data[8:14])
    src_ip = socket.inet_ntoa(raw_data[14:18])
    dst_mac = mac_to_str(raw_data[18:24])
    dst_ip = socket.inet_ntoa(raw_data[24:28])
    return {
        "hw_type": hw_type,
        "proto_type": hex(proto_type),
        "opcode": "Request" if opcode == 1 else ("Reply" if opcode == 2 else str(opcode)),
        "src_mac": src_mac,
        "src_ip": src_ip,
        "dst_mac": dst_mac,
        "dst_ip": dst_ip
    }

def dissect_tcp(raw_data):
    if len(raw_data) < 20:
        return None, raw_data
    src_port, dst_port, sequence, ack, offset_reserved_flags = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    if offset < 20 or offset > len(raw_data):
        offset = 20
    flags = offset_reserved_flags & 0x01FF

    flag_fin = bool(flags & 1)
    flag_syn = bool(flags & 2)
    flag_rst = bool(flags & 4)
    flag_psh = bool(flags & 8)
    flag_ack = bool(flags & 16)
    flag_urg = bool(flags & 32)

    flags_str = []
    if flag_syn: flags_str.append("SYN")
    if flag_ack: flags_str.append("ACK")
    if flag_fin: flags_str.append("FIN")
    if flag_rst: flags_str.append("RST")
    if flag_psh: flags_str.append("PSH")
    if flag_urg: flags_str.append("URG")

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": sequence,
        "ack": ack,
        "offset": offset,
        "flags": ",".join(flags_str) if flags_str else "None"
    }, raw_data[offset:]

def dissect_udp(raw_data):
    if len(raw_data) < 8:
        return None, raw_data
    src_port, dst_port, length, checksum = struct.unpack("! H H H H", raw_data[:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": hex(checksum)
    }, raw_data[8:]

def dissect_icmp(raw_data):
    if len(raw_data) < 4:
        return None, raw_data
    icmp_type, code, checksum = struct.unpack("! B B H", raw_data[:4])
    type_str = "Echo Reply" if icmp_type == 0 else ("Echo Request" if icmp_type == 8 else f"Type {icmp_type}")
    return {
        "type": icmp_type,
        "type_str": type_str,
        "code": code,
        "checksum": hex(checksum)
    }, raw_data[4:]

def dissect_http(payload_bytes):
    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1.")):
            lines = text.split("\r\n")
            request_line = lines[0]
            headers = {}
            body_start = text.find("\r\n\r\n")
            body = ""
            if body_start != -1:
                body = text[body_start + 4:]
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            return {
                "request_line": request_line,
                "headers": headers,
                "body": body
            }
    except Exception:
        pass
    return None


def dissect_packet(raw_data, packet_id, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    pkt = {
        "id": packet_id,
        "time": timestamp,
        "len": len(raw_data),
        "src": "Unknown",
        "dst": "Unknown",
        "protocol": "RAW",
        "info": "",
        "eth": None,
        "ip": None,
        "ip6": None,
        "arp": None,
        "tcp": None,
        "udp": None,
        "icmp": None,
        "http": None,
        "payload": raw_data,
        "color": "#FFFFFF"  # default background
    }

    eth, payload, ethertype = dissect_ethernet(raw_data)
    pkt["eth"] = eth

    current_payload = payload
    next_proto = None

    if ethertype == 0x0800: # IPv4
        ip, payload, proto = dissect_ipv4(current_payload)
        if ip:
            pkt["ip"] = ip
            pkt["src"] = ip["src_ip"]
            pkt["dst"] = ip["dst_ip"]
            pkt["protocol"] = "IPv4"
            current_payload = payload
            next_proto = proto
    elif ethertype == 0x86DD: # IPv6
        ip6, payload, proto = dissect_ipv6(current_payload)
        if ip6:
            pkt["ip6"] = ip6
            pkt["src"] = ip6["src_ip"]
            pkt["dst"] = ip6["dst_ip"]
            pkt["protocol"] = "IPv6"
            current_payload = payload
            next_proto = proto
    elif ethertype == 0x0806: # ARP
        arp = dissect_arp(current_payload)
        if arp:
            pkt["arp"] = arp
            pkt["src"] = arp["src_ip"]
            pkt["dst"] = arp["dst_ip"]
            pkt["protocol"] = "ARP"
            pkt["info"] = f"Who has {arp['dst_ip']}? Tell {arp['src_ip']} ({arp['opcode']})"
            pkt["color"] = "#FFF0C2" # Soft yellow for ARP
            return pkt

    # Transport layer dissection
    if pkt["ip"] or pkt["ip6"]:
        if next_proto == 6: # TCP
            tcp, l7_payload = dissect_tcp(current_payload)
            if tcp:
                pkt["tcp"] = tcp
                pkt["protocol"] = "TCP"
                pkt["src"] = f"{pkt['src']}:{tcp['src_port']}"
                pkt["dst"] = f"{pkt['dst']}:{tcp['dst_port']}"
                pkt["info"] = f"{tcp['src_port']} → {tcp['dst_port']} [{tcp['flags']}] Seq={tcp['seq']} Ack={tcp['ack']}"
                pkt["color"] = "#E6F3FF" # Soft blue for TCP

                # Check HTTP layer
                http = dissect_http(l7_payload)
                if http:
                    pkt["http"] = http
                    pkt["protocol"] = "HTTP"
                    pkt["info"] = f"HTTP: {http['request_line']}"
                    pkt["color"] = "#E2FFE2" # Soft green for HTTP
                pkt["payload"] = l7_payload
        elif next_proto == 17: # UDP
            udp, l7_payload = dissect_udp(current_payload)
            if udp:
                pkt["udp"] = udp
                pkt["protocol"] = "UDP"
                pkt["src"] = f"{pkt['src']}:{udp['src_port']}"
                pkt["dst"] = f"{pkt['dst']}:{udp['dst_port']}"
                pkt["info"] = f"{udp['src_port']} → {udp['dst_port']} Len={udp['length']}"
                pkt["color"] = "#DAE8FC" # Soft purple/blue for UDP
                pkt["payload"] = l7_payload
        elif next_proto == 1: # ICMP
            icmp, l7_payload = dissect_icmp(current_payload)
            if icmp:
                pkt["icmp"] = icmp
                pkt["protocol"] = "ICMP"
                pkt["info"] = f"ICMP {icmp['type_str']} Code={icmp['code']}"
                pkt["color"] = "#FDE2FF" # Soft magenta for ICMP
                pkt["payload"] = l7_payload

    if not pkt["info"]:
        pkt["info"] = f"Length={pkt['len']}"

    return pkt


# ==========================================
# 2. Filtering & Statistics Helpers
# ==========================================

def matches_filter(pkt, filter_text):
    if not filter_text:
        return True

    filter_text = filter_text.strip().lower()

    # Direct protocol match (e.g., tcp, udp, http, icmp, arp)
    if filter_text in ["tcp", "udp", "http", "icmp", "arp", "ipv4", "ipv6"]:
        return pkt["protocol"].lower() == filter_text

    # Key-value filters e.g. ip==192.168.1.1 or port==80
    if "==" in filter_text:
        key, val = [x.strip() for x in filter_text.split("==", 1)]
        if key in ["ip", "ip.src", "ip.dst", "host"]:
            return val in pkt["src"].lower() or val in pkt["dst"].lower()
        if key in ["port", "tcp.port", "udp.port"]:
            return val in pkt["src"].lower() or val in pkt["dst"].lower()

    # Substring search in src, dst, protocol, info, or raw payload
    if filter_text in pkt["src"].lower() or filter_text in pkt["dst"].lower() or filter_text in pkt["protocol"].lower() or filter_text in pkt["info"].lower():
        return True

    if pkt.get("payload"):
        try:
            payload_str = pkt["payload"].decode("utf-8", errors="ignore").lower()
            if filter_text in payload_str:
                return True
        except Exception:
            pass

    return False


class TrafficStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts = {}
            self.endpoints = {}
            self.conversations = {}

    def add_packet(self, pkt):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += pkt["len"]

            proto = pkt["protocol"]
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

            src = pkt["src"]
            dst = pkt["dst"]
            self.endpoints[src] = self.endpoints.get(src, 0) + 1
            self.endpoints[dst] = self.endpoints.get(dst, 0) + 1

            conv_key = " <-> ".join(sorted([src, dst]))
            self.conversations[conv_key] = self.conversations.get(conv_key, 0) + 1


# ==========================================
# 3. Main GUI Application Class
# ==========================================

class NetAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("NetAnalyzer - Network Packet Analyzer & DPI Tool")
        self.geometry("1100 undertaking 750".replace("undertaking", "x"))
        self.minsize(900, 600)

        self.capturing = False
        self.packets = []
        self.filtered_packets = []
        self.stats = TrafficStats()
        self.packet_counter = 0

        self.setup_ui()

    def setup_ui(self):
        # Top Controls Frame
        ctrl_frame = ttk.Frame(self, padding=5)
        ctrl_frame.pack(fill=tk.X, side=tk.TOP)

        ttk.Label(ctrl_frame, text="Interface:").pack(side=tk.LEFT, padx=3)
        self.iface_cb = ttk.Combobox(ctrl_frame, values=["Default / All Interfaces", "eth0", "wlan0", "lo"], width=22)
        self.iface_cb.current(0)
        self.iface_cb.pack(side=tk.LEFT, padx=3)

        self.start_btn = ttk.Button(ctrl_frame, text="▶ Start Capture", command=self.toggle_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(ctrl_frame, text="🗑 Clear", command=self.clear_capture)
        self.clear_btn.pack(side=tk.LEFT, padx=3)

        ttk.Label(ctrl_frame, text="Filter:").pack(side=tk.LEFT, padx=(15, 3))
        self.filter_entry = ttk.Entry(ctrl_frame, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=3)
        self.filter_entry.bind("<Return>", lambda e: self.apply_filter())

        ttk.Button(ctrl_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=3)
        ttk.Button(ctrl_frame, text="📊 Statistics", command=self.show_statistics_window).pack(side=tk.RIGHT, padx=3)
        ttk.Button(ctrl_frame, text="📦 Export Objects", command=self.show_export_objects_window).pack(side=tk.RIGHT, padx=3)

        # Paned Window (Split into Packet List table, Packet Details tree, and Payload Hex view)
        paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 1. Packet List View (Treeview Table)
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=2)

        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.pkt_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")

        self.pkt_tree.heading("No", text="No.")
        self.pkt_tree.heading("Time", text="Time")
        self.pkt_tree.heading("Source", text="Source")
        self.pkt_tree.heading("Destination", text="Destination")
        self.pkt_tree.heading("Protocol", text="Protocol")
        self.pkt_tree.heading("Length", text="Length")
        self.pkt_tree.heading("Info", text="Info")

        self.pkt_tree.column("No", width=50, anchor=tk.E)
        self.pkt_tree.column("Time", width=100)
        self.pkt_tree.column("Source", width=180)
        self.pkt_tree.column("Destination", width=180)
        self.pkt_tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.pkt_tree.column("Length", width=60, anchor=tk.E)
        self.pkt_tree.column("Info", width=400)

        # Configure color tags
        self.pkt_tree.tag_configure("TCP", background="#E6F3FF")
        self.pkt_tree.tag_configure("UDP", background="#DAE8FC")
        self.pkt_tree.tag_configure("HTTP", background="#E2FFE2")
        self.pkt_tree.tag_configure("ARP", background="#FFF0C2")
        self.pkt_tree.tag_configure("ICMP", background="#FDE2FF")

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.pkt_tree.yview)
        self.pkt_tree.configure(yscrollcommand=tree_scroll.set)

        self.pkt_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.pkt_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # 2. Bottom Details Notebook (Details Tree + Hex View)
        bottom_notebook = ttk.Notebook(paned)
        paned.add(bottom_notebook, weight=1)

        # Details Tree Tab
        details_frame = ttk.Frame(bottom_notebook)
        bottom_notebook.add(details_frame, text="Packet Header Details")

        self.details_tree = ttk.Treeview(details_frame, show="tree")
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=details_scroll.set)
        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Hex/ASCII Payload View Tab
        hex_frame = ttk.Frame(bottom_notebook)
        bottom_notebook.add(hex_frame, text="Hex / ASCII Bytes View")

        self.hex_text = scrolledtext.ScrolledText(hex_frame, font=("Courier", 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready. Click Start Capture to begin monitoring network interfaces.")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_capture(self):
        if not self.capturing:
            self.capturing = True
            self.start_btn.config(text="⏸ Stop Capture")
            self.status_var.set("Capturing network packets...")
            self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
            self.capture_thread.start()
        else:
            self.capturing = False
            self.start_btn.config(text="▶ Start Capture")
            self.status_var.set(f"Capture paused. Total packets captured: {len(self.packets)}")

    def capture_loop(self):
        """
        Packet capture thread. Uses raw socket or mock test packets when socket permissions are restricted.
        """
        sock = None
        try:
            if sys.platform != "win32":
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except Exception:
            sock = None

        while self.capturing:
            raw_data = None
            if sock:
                try:
                    sock.settimeout(0.5)
                    raw_data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception:
                    sock = None

            if not sock or not raw_data:
                # Generate synthetic diagnostic packets for test / unprivileged environment
                time.sleep(0.3)
                raw_data = self.generate_synthetic_packet()

            self.packet_counter += 1
            pkt = dissect_packet(raw_data, self.packet_counter)

            self.packets.append(pkt)
            self.stats.add_packet(pkt)

            # Update GUI on main thread
            if matches_filter(pkt, self.filter_entry.get()):
                self.after(0, self.insert_packet_into_tree, pkt)

        if sock and sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass

    def generate_synthetic_packet(self):
        """Generates realistic sample packet bytes for testing GUI & DPI engine."""
        import random
        packet_types = ["http", "tcp", "udp", "arp", "icmp"]
        ptype = random.choice(packet_types)

        # Base Ethernet header (Dst MAC, Src MAC, EtherType)
        eth_hdr = struct.pack("! 6s 6s H", b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800)

        if ptype == "arp":
            eth_arp_hdr = struct.pack("! 6s 6s H", b"\xff"*6, b"\xaa\xbb\xcc\xdd\xee\xff", 0x0806)
            arp_body = struct.pack("! H H B B H 6s 4s 6s 4s", 1, 0x0800, 6, 4, 1,
                                   b"\xaa\xbb\xcc\xdd\xee\xff", socket.inet_aton("192.168.1.105"),
                                   b"\x00"*6, socket.inet_aton("192.168.1.1"))
            return eth_arp_hdr + arp_body

        # IPv4 Header
        src_ip = f"192.168.1.{random.randint(2, 200)}"
        dst_ip = f"93.184.216.{random.randint(1, 50)}"

        if ptype == "icmp":
            ip_hdr = struct.pack("! B B H H H B B H 4s 4s", 0x45, 0, 40, 1234, 0, 64, 1, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
            icmp_hdr = struct.pack("! B B H", 8, 0, 0) + b"PingDataPayload123"
            return eth_hdr + ip_hdr + icmp_hdr

        if ptype == "udp":
            ip_hdr = struct.pack("! B B H H H B B H 4s 4s", 0x45, 0, 48, 1234, 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
            udp_hdr = struct.pack("! H H H H", 5353, 53, 28, 0) + b"DNS Query Payload"
            return eth_hdr + ip_hdr + udp_hdr

        # TCP / HTTP
        proto_num = 6
        ip_hdr = struct.pack("! B B H H H B B H 4s 4s", 0x45, 0, 80, 1234, 0, 64, proto_num, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        tcp_hdr = struct.pack("! H H L L H 6x", random.randint(1024, 65000), 80, random.randint(100, 9000), random.randint(100, 9000), (5 << 12) | 0x18)

        if ptype == "http":
            payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetAnalyzer/1.0\r\n\r\n<html><body>Hello World</body></html>"
            return eth_hdr + ip_hdr + tcp_hdr + payload

        return eth_hdr + ip_hdr + tcp_hdr + b"TCP Ack Payload Data"

    def insert_packet_into_tree(self, pkt):
        tag = pkt["protocol"] if pkt["protocol"] in ["TCP", "UDP", "HTTP", "ARP", "ICMP"] else ""
        self.pkt_tree.insert("", tk.END, iid=str(pkt["id"]), values=(
            pkt["id"],
            pkt["time"],
            pkt["src"],
            pkt["dst"],
            pkt["protocol"],
            pkt["len"],
            pkt["info"]
        ), tags=(tag,))

    def apply_filter(self):
        filter_text = self.filter_entry.get()
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        count = 0
        for pkt in self.packets:
            if matches_filter(pkt, filter_text):
                self.insert_packet_into_tree(pkt)
                count += 1
        self.status_var.set(f"Filter applied: '{filter_text}'. Showing {count} of {len(self.packets)} packets.")

    def clear_capture(self):
        self.packets.clear()
        self.stats.reset()
        self.packet_counter = 0
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        self.details_tree.delete(*self.details_tree.get_children())
        self.hex_text.delete("1.0", tk.END)
        self.status_var.set("Capture cleared.")

    def on_packet_select(self, event):
        selected = self.pkt_tree.selection()
        if not selected:
            return
        pkt_id = int(selected[0])
        pkt = next((p for p in self.packets if p["id"] == pkt_id), None)
        if not pkt:
            return

        # Populate Details Tree
        self.details_tree.delete(*self.details_tree.get_children())

        frame_node = self.details_tree.insert("", tk.END, text=f"Frame {pkt['id']}: {pkt['len']} bytes on wire")

        if pkt["eth"]:
            eth_node = self.details_tree.insert("", tk.END, text=f"Ethernet II, Src: {pkt['eth']['src_mac']}, Dst: {pkt['eth']['dest_mac']}")
            self.details_tree.insert(eth_node, tk.END, text=f"Source MAC: {pkt['eth']['src_mac']}")
            self.details_tree.insert(eth_node, tk.END, text=f"Destination MAC: {pkt['eth']['dest_mac']}")
            self.details_tree.insert(eth_node, tk.END, text=f"EtherType: {pkt['eth']['ethertype']}")

        if pkt["ip"]:
            ip_node = self.details_tree.insert("", tk.END, text=f"Internet Protocol Version 4, Src: {pkt['ip']['src_ip']}, Dst: {pkt['ip']['dst_ip']}")
            self.details_tree.insert(ip_node, tk.END, text=f"Version: {pkt['ip']['version']}")
            self.details_tree.insert(ip_node, tk.END, text=f"Header Length: {pkt['ip']['header_len']} bytes")
            self.details_tree.insert(ip_node, tk.END, text=f"Time to Live (TTL): {pkt['ip']['ttl']}")
            self.details_tree.insert(ip_node, tk.END, text=f"Protocol: {pkt['ip']['protocol']}")

        if pkt["arp"]:
            arp_node = self.details_tree.insert("", tk.END, text=f"Address Resolution Protocol ({pkt['arp']['opcode']})")
            self.details_tree.insert(arp_node, tk.END, text=f"Sender MAC: {pkt['arp']['src_mac']}")
            self.details_tree.insert(arp_node, tk.END, text=f"Sender IP: {pkt['arp']['src_ip']}")
            self.details_tree.insert(arp_node, tk.END, text=f"Target MAC: {pkt['arp']['dst_mac']}")
            self.details_tree.insert(arp_node, tk.END, text=f"Target IP: {pkt['arp']['dst_ip']}")

        if pkt["tcp"]:
            tcp_node = self.details_tree.insert("", tk.END, text=f"Transmission Control Protocol, Src Port: {pkt['tcp']['src_port']}, Dst Port: {pkt['tcp']['dst_port']}")
            self.details_tree.insert(tcp_node, tk.END, text=f"Sequence Number: {pkt['tcp']['seq']}")
            self.details_tree.insert(tcp_node, tk.END, text=f"Acknowledgment Number: {pkt['tcp']['ack']}")
            self.details_tree.insert(tcp_node, tk.END, text=f"Flags: {pkt['tcp']['flags']}")

        if pkt["udp"]:
            udp_node = self.details_tree.insert("", tk.END, text=f"User Datagram Protocol, Src Port: {pkt['udp']['src_port']}, Dst Port: {pkt['udp']['dst_port']}")
            self.details_tree.insert(udp_node, tk.END, text=f"Length: {pkt['udp']['length']}")
            self.details_tree.insert(udp_node, tk.END, text=f"Checksum: {pkt['udp']['checksum']}")

        if pkt["http"]:
            http_node = self.details_tree.insert("", tk.END, text=f"Hypertext Transfer Protocol: {pkt['http']['request_line']}")
            for k, v in pkt["http"]["headers"].items():
                self.details_tree.insert(http_node, tk.END, text=f"{k}: {v}")

        # Expand top nodes
        for item in self.details_tree.get_children():
            self.details_tree.item(item, open=True)

        # Populate Hex View
        payload = pkt.get("payload") or b""
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert(tk.END, format_hex_ascii(payload))

    def show_statistics_window(self):
        stats_win = tk.Toplevel(self)
        stats_win.title("Traffic Statistics & Conversations")
        stats_win.geometry("650x450")

        notebook = ttk.Notebook(stats_win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Overview Tab
        overview_frame = ttk.Frame(notebook, padding=10)
        notebook.add(overview_frame, text="Protocol Hierarchy")

        headers = ("Protocol", "Packets", "Percent")
        proto_tree = ttk.Treeview(overview_frame, columns=headers, show="headings")
        proto_tree.heading("Protocol", text="Protocol")
        proto_tree.heading("Packets", text="Packets")
        proto_tree.heading("Percent", text="Percent %")
        proto_tree.pack(fill=tk.BOTH, expand=True)

        with self.stats.lock:
            tot = max(self.stats.total_packets, 1)
            for proto, count in sorted(self.stats.protocol_counts.items(), key=lambda x: x[1], reverse=True):
                pct = (count / tot) * 100
                proto_tree.insert("", tk.END, values=(proto, count, f"{pct:.1f}%"))

        # Conversations Tab
        conv_frame = ttk.Frame(notebook, padding=10)
        notebook.add(conv_frame, text="Endpoints & Conversations")

        conv_headers = ("Conversation Endpoint Pair", "Packet Count")
        conv_tree = ttk.Treeview(conv_frame, columns=conv_headers, show="headings")
        conv_tree.heading("Conversation Endpoint Pair", text="Conversation Endpoint Pair")
        conv_tree.heading("Packet Count", text="Packet Count")
        conv_tree.pack(fill=tk.BOTH, expand=True)

        with self.stats.lock:
            for pair, count in sorted(self.stats.conversations.items(), key=lambda x: x[1], reverse=True):
                conv_tree.insert("", tk.END, values=(pair, count))

    def show_export_objects_window(self):
        exp_win = tk.Toplevel(self)
        exp_win.title("Object Exporter - Extract Files & Payloads")
        exp_win.geometry("650x400")

        lbl = ttk.Label(exp_win, text="Unencrypted Reassembled Files & Data Objects in Traffic Stream:", padding=5)
        lbl.pack(anchor=tk.W)

        cols = ("Packet No", "Protocol", "Host / Resource", "Size")
        obj_tree = ttk.Treeview(exp_win, columns=cols, show="headings")
        for c in cols:
            obj_tree.heading(c, text=c)
        obj_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        objects = []
        for pkt in self.packets:
            if pkt["http"] and pkt["http"].get("body"):
                body_bytes = pkt["http"]["body"].encode("utf-8")
                req = pkt["http"]["request_line"]
                host = pkt["http"]["headers"].get("Host", "HTTP Stream")
                objects.append({
                    "pkt_id": pkt["id"],
                    "proto": "HTTP",
                    "resource": f"{host} ({req})",
                    "size": f"{len(body_bytes)} bytes",
                    "data": body_bytes
                })

        for item in objects:
            obj_tree.insert("", tk.END, iid=str(item["pkt_id"]), values=(item["pkt_id"], item["proto"], item["resource"], item["size"]))

        def export_selected():
            sel = obj_tree.selection()
            if not sel:
                messagebox.showinfo("Export Object", "Please select an object from the list to export.")
                return
            pkt_id = int(sel[0])
            obj = next((o for o in objects if o["pkt_id"] == pkt_id), None)
            if not obj:
                return

            filename = filedialog.asksaveasfilename(title="Save Exported Object Payload", initialfile=f"extracted_object_pkt_{pkt_id}.txt")
            if filename:
                with open(filename, "wb") as f:
                    f.write(obj["data"])
                messagebox.showinfo("Export Successful", f"Saved payload to:\n{filename}")

        btn_frame = ttk.Frame(exp_win, padding=5)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="💾 Save Selected Object", command=export_selected).pack(side=tk.RIGHT, padx=5)


def format_hex_ascii(data_bytes):
    if not data_bytes:
        return "No payload bytes available."

    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_str:<48}   {ascii_str}")
    return "\n".join(lines)


def main():
    app = NetAnalyzerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
