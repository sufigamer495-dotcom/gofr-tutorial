import unittest
import netdiag

class TestNetDiag(unittest.TestCase):

    def test_parse_netsh_output(self):
        sample_netsh_output = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNetwork_5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 85%
         Radio type         : 802.11ax
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54

SSID 2 : Guest_WiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 6
"""
        networks = netdiag.parse_netsh_output(sample_netsh_output)
        self.assertEqual(len(networks), 2)

        net1 = networks[0]
        self.assertEqual(net1["ssid"], "HomeNetwork_5G")
        self.assertEqual(net1["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(net1["signal_percent"], 85)
        self.assertEqual(net1["rssi_dbm"], -57)
        self.assertEqual(net1["channel"], 36)
        self.assertEqual(net1["authentication"], "WPA2-Personal")

        net2 = networks[1]
        self.assertEqual(net2["ssid"], "Guest_WiFi")
        self.assertEqual(net2["bssid"], "11:22:33:44:55:66")
        self.assertEqual(net2["signal_percent"], 40)
        self.assertEqual(net2["rssi_dbm"], -80)
        self.assertEqual(net2["channel"], 6)

    def test_expand_ip_range(self):
        # Single IP
        single = netdiag.expand_target_ip_range("192.168.1.10")
        self.assertEqual(single, ["192.168.1.10"])

        # Range notation
        ip_range = netdiag.expand_target_ip_range("192.168.1.1-192.168.1.5")
        self.assertEqual(ip_range, ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"])

        # Short range notation
        short_range = netdiag.expand_target_ip_range("10.0.0.1-3")
        self.assertEqual(short_range, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        # CIDR notation
        cidr = netdiag.expand_target_ip_range("192.168.1.0/30")
        self.assertEqual(cidr, ["192.168.1.1", "192.168.1.2"])

    def test_channel_interference(self):
        sample_networks = [
            {"channel": 6},
            {"channel": 6},
            {"channel": 11},
            {"channel": 1},
            {"channel": 6}
        ]
        counts = netdiag.analyze_channel_interference(sample_networks)
        self.assertEqual(counts.get(6), 3)
        self.assertEqual(counts.get(11), 1)
        self.assertEqual(counts.get(1), 1)

    def test_ssl_cert_check(self):
        # Test SSL inspection against public test server (or invalid port error handling)
        res = netdiag.inspect_ssl_certificate("127.0.0.1", port=9999, timeout=0.5)
        self.assertFalse(res["has_ssl"])
        self.assertIn("error", res)

    def test_port_scan(self):
        # Check closed port logic
        res = netdiag.check_single_port("127.0.0.1", 59999, timeout=0.5, check_ssl=False)
        self.assertEqual(res["port"], 59999)
        self.assertEqual(res["state"], "Closed / Filtered")

if __name__ == "__main__":
    unittest.main()
