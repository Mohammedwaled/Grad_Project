import copy
import sys
import unittest
from pathlib import Path

# السماح باستيراد validate_config من فولدر src
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from validate_config import (  # noqa: E402
    DEFAULT_DATA_FILE,
    DEFAULT_SCHEMA_FILE,
    load_json,
    validate_config,
    validate_data,
)

SCHEMA = load_json(DEFAULT_SCHEMA_FILE)

# شبكة سليمة نبني عليها كل حالات الاختبار
VALID_NETWORK = {
    "network_name": "CyberDT-Lab",
    "devices": [
        {
            "id": "web-01",
            "type": "web_server",
            "criticality": "high",
            "ports": [443],
            "services": [
                {
                    "name": "https",
                    "port": 443,
                    "protocol": "TCP",
                    "version": "Apache 2.4.49",
                    "vulnerabilities": [{"id": "CVE-2021-41773", "cvss": 7.5}],
                }
            ],
        },
        {
            "id": "db-01",
            "type": "database",
            "criticality": "critical",
            "ports": [3306],
            "services": [{"name": "mysql", "port": 3306, "protocol": "TCP"}],
        },
    ],
    "connections": [
        {"source": "web-01", "target": "db-01", "port": 3306, "protocol": "TCP"}
    ],
}


class ValidateConfigTests(unittest.TestCase):
    def assert_invalid(self, data, expected_text):
        is_valid, errors = validate_data(data, SCHEMA)
        self.assertFalse(is_valid, "config should have been rejected")
        joined = "\n".join(errors)
        self.assertIn(expected_text, joined)

    def make(self):
        return copy.deepcopy(VALID_NETWORK)

    # ---------- الحالة السليمة ----------
    def test_valid_network_passes(self):
        is_valid, errors = validate_data(self.make(), SCHEMA)
        self.assertTrue(is_valid, errors)

    def test_real_network_json_passes(self):
        is_valid, errors = validate_config(DEFAULT_DATA_FILE, DEFAULT_SCHEMA_FILE)
        self.assertTrue(is_valid, errors)

    # ---------- فحوصات الـ Schema ----------
    def test_port_out_of_range(self):
        data = self.make()
        data["devices"][1]["ports"] = [70000]
        self.assert_invalid(data, "devices[1].ports[0]")

    def test_port_zero(self):
        data = self.make()
        data["devices"][0]["ports"] = [0]
        self.assert_invalid(data, "devices[0].ports[0]")

    def test_duplicate_ports_in_device(self):
        data = self.make()
        data["devices"][0]["ports"] = [443, 443]
        self.assert_invalid(data, "devices[0].ports")

    def test_bad_protocol(self):
        data = self.make()
        data["connections"][0]["protocol"] = "ICMP"
        self.assert_invalid(data, "connections[0].protocol")

    def test_empty_devices(self):
        data = self.make()
        data["devices"] = []
        data["connections"] = []
        self.assert_invalid(data, "devices")

    def test_empty_device_id(self):
        data = self.make()
        data["devices"][0]["id"] = ""
        self.assert_invalid(data, "devices[0].id")

    def test_unknown_device_type(self):
        data = self.make()
        data["devices"][0]["type"] = "web_servr"
        self.assert_invalid(data, "devices[0].type")

    def test_extra_property_typo(self):
        data = self.make()
        data["devices"][0]["prots"] = [22]
        self.assert_invalid(data, "prots")

    def test_missing_required_field(self):
        data = self.make()
        del data["devices"][0]["ports"]
        self.assert_invalid(data, "ports")

    # ---------- فحوصات العلاقات (Cross-reference) ----------
    def test_unknown_target(self):
        data = self.make()
        data["connections"][0]["target"] = "db-99"
        self.assert_invalid(data, "unknown device 'db-99'")

    def test_unknown_source(self):
        data = self.make()
        data["connections"][0]["source"] = "ghost-01"
        self.assert_invalid(data, "unknown device 'ghost-01'")

    def test_port_not_open_on_target(self):
        data = self.make()
        data["connections"][0]["port"] = 8080
        self.assert_invalid(data, "port 8080 is not open on target 'db-01'")

    def test_duplicate_device_id(self):
        data = self.make()
        data["devices"][1]["id"] = "web-01"
        self.assert_invalid(data, "duplicate id 'web-01'")


    # ---------- الجزء الجديد: Criticality / Services / Vulnerabilities ----------
    def test_missing_criticality(self):
        data = self.make()
        del data["devices"][0]["criticality"]
        self.assert_invalid(data, "criticality")

    def test_unknown_criticality_level(self):
        data = self.make()
        data["devices"][0]["criticality"] = "urgent"
        self.assert_invalid(data, "devices[0].criticality")

    def test_cvss_out_of_range(self):
        data = self.make()
        data["devices"][0]["services"][0]["vulnerabilities"][0]["cvss"] = 11
        self.assert_invalid(data, "cvss")

    def test_vulnerability_missing_id(self):
        data = self.make()
        del data["devices"][0]["services"][0]["vulnerabilities"][0]["id"]
        self.assert_invalid(data, "id")

    def test_service_port_not_in_device_ports(self):
        data = self.make()
        data["devices"][0]["services"][0]["port"] = 8443
        self.assert_invalid(data, "not in the device ports")

    def test_duplicate_service_on_same_port(self):
        data = self.make()
        data["devices"][0]["services"].append(
            {"name": "https-alt", "port": 443, "protocol": "TCP"}
        )
        self.assert_invalid(data, "duplicate service on TCP/443")


if __name__ == "__main__":
    unittest.main()
