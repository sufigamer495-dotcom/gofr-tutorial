import unittest
import struct
import socket
import netanalyzer_gui

class TestNetAnalyzer(unittest.TestCase):

    def setUp(self):
        # Create a synthetic IPv4 HTTP packet over Ethernet
        eth_hdr = struct.pack("! 6s 6s H", b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800)
        ip_hdr = struct.pack("! B B H H H B B H 4s 4s", 0x45, 0, 80, 1234, 0, 64, 6, 0, socket.inet_aton("192.168.1.50"), socket.inet_aton("93.184.216.34"))
        # TCP Header (20 bytes minimum: SrcPort, DstPort, Seq, Ack, OffsetFlags, Window, Checksum, UrgPtr)
        tcp_hdr = struct.pack("! H H L L H H H H", 54321, 80, 1000, 2000, (5 << 12) | 0x18, 64240, 0, 0)
        self.http_body = "<html><body>Test Object Payload</body></html>"
        self.http_payload = f"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n{self.http_body}".encode("utf-8")
        self.raw_http_packet = eth_hdr + ip_hdr + tcp_hdr + self.http_payload

        # Create ARP packet
        eth_arp_hdr = struct.pack("! 6s 6s H", b"\xff"*6, b"\xaa\xbb\xcc\xdd\xee\xff", 0x0806)
        arp_body = struct.pack("! H H B B H 6s 4s 6s 4s", 1, 0x0800, 6, 4, 1,
                               b"\xaa\xbb\xcc\xdd\xee\xff", socket.inet_aton("192.168.1.100"),
                               b"\x00"*6, socket.inet_aton("192.168.1.1"))
        self.raw_arp_packet = eth_arp_hdr + arp_body

    def test_packet_dissect_http(self):
        pkt = netanalyzer_gui.dissect_packet(self.raw_http_packet, 1)
        self.assertEqual(pkt["id"], 1)
        self.assertEqual(pkt["protocol"], "HTTP")
        self.assertEqual(pkt["src"], "192.168.1.50:54321")
        self.assertEqual(pkt["dst"], "93.184.216.34:80")
        self.assertIsNotNone(pkt["eth"])
        self.assertIsNotNone(pkt["ip"])
        self.assertIsNotNone(pkt["tcp"])
        self.assertIsNotNone(pkt["http"])
        self.assertEqual(pkt["http"]["request_line"], "GET /index.html HTTP/1.1")
        self.assertEqual(pkt["http"]["headers"].get("Host"), "example.com")
        self.assertEqual(pkt["http"]["body"], self.http_body)

    def test_packet_dissect_arp(self):
        pkt = netanalyzer_gui.dissect_packet(self.raw_arp_packet, 2)
        self.assertEqual(pkt["protocol"], "ARP")
        self.assertEqual(pkt["src"], "192.168.1.100")
        self.assertEqual(pkt["dst"], "192.168.1.1")
        self.assertIsNotNone(pkt["arp"])
        self.assertEqual(pkt["arp"]["opcode"], "Request")

    def test_packet_filtering(self):
        pkt_http = netanalyzer_gui.dissect_packet(self.raw_http_packet, 1)
        pkt_arp = netanalyzer_gui.dissect_packet(self.raw_arp_packet, 2)

        # Protocol filter
        self.assertTrue(netanalyzer_gui.matches_filter(pkt_http, "http"))
        self.assertFalse(netanalyzer_gui.matches_filter(pkt_arp, "http"))
        self.assertTrue(netanalyzer_gui.matches_filter(pkt_arp, "arp"))

        # IP filter
        self.assertTrue(netanalyzer_gui.matches_filter(pkt_http, "ip==192.168.1.50"))
        self.assertFalse(netanalyzer_gui.matches_filter(pkt_http, "ip==10.0.0.1"))

        # Keyword search
        self.assertTrue(netanalyzer_gui.matches_filter(pkt_http, "example.com"))

    def test_stats_aggregation(self):
        stats = netanalyzer_gui.TrafficStats()
        pkt1 = netanalyzer_gui.dissect_packet(self.raw_http_packet, 1)
        pkt2 = netanalyzer_gui.dissect_packet(self.raw_arp_packet, 2)

        stats.add_packet(pkt1)
        stats.add_packet(pkt2)

        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.protocol_counts["HTTP"], 1)
        self.assertEqual(stats.protocol_counts["ARP"], 1)

    def test_format_hex_ascii(self):
        sample_bytes = b"Hello World 1234"
        output = netanalyzer_gui.format_hex_ascii(sample_bytes)
        self.assertIn("48 65 6c 6c 6f", output)
        self.assertIn("Hello World 1234", output)


if __name__ == "__main__":
    unittest.main()
