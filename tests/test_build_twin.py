import copy
import sys
import tempfile
import json
import unittest
from pathlib import Path

# السماح باستيراد build_twin من فولدر src
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from build_twin import (  # noqa: E402
    build_twin,
    build_twin_from_file,
    cvss_to_severity,
    format_summary,
)

NETWORK = {
    "network_name": "Test-Lab",
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
                    "vulnerabilities": [
                        {"id": "CVE-A", "cvss": 7.5},
                        {"id": "CVE-B", "cvss": 9.8},
                    ],
                }
            ],
        },
        {
            "id": "db-01",
            "type": "database",
            "criticality": "critical",
            "ports": [3306, 3307],
            "services": [{"name": "mysql", "port": 3306, "protocol": "TCP"}],
        },
    ],
    "connections": [
        {"source": "web-01", "target": "db-01", "port": 3306, "protocol": "TCP"},
        {"source": "web-01", "target": "db-01", "port": 3307, "protocol": "TCP"},
    ],
}


class BuildTwinTests(unittest.TestCase):
    def setUp(self):
        self.twin = build_twin(copy.deepcopy(NETWORK))

    def test_nodes_and_edges_count(self):
        self.assertEqual(self.twin.number_of_nodes(), 2)
        self.assertEqual(self.twin.number_of_edges(), 2)

    def test_multiple_connections_between_same_devices_are_kept(self):
        ports = sorted(d["port"] for _, _, d in self.twin.edges(data=True))
        self.assertEqual(ports, [3306, 3307])

    def test_edge_direction(self):
        self.assertTrue(self.twin.has_edge("web-01", "db-01"))
        self.assertFalse(self.twin.has_edge("db-01", "web-01"))

    def test_criticality_score(self):
        self.assertEqual(self.twin.nodes["web-01"]["criticality_score"], 3)
        self.assertEqual(self.twin.nodes["db-01"]["criticality_score"], 4)

    def test_vulnerabilities_linked_to_service(self):
        vulns = self.twin.nodes["web-01"]["vulnerabilities"]
        self.assertEqual(len(vulns), 2)
        self.assertTrue(all(v["service"] == "https" and v["port"] == 443 for v in vulns))

    def test_max_cvss(self):
        self.assertEqual(self.twin.nodes["web-01"]["max_cvss"], 9.8)
        self.assertEqual(self.twin.nodes["db-01"]["max_cvss"], 0.0)

    def test_device_without_vulnerabilities(self):
        self.assertEqual(self.twin.nodes["db-01"]["vulnerabilities"], [])

    def test_cvss_severity_boundaries(self):
        cases = {0: "none", 0.1: "low", 3.9: "low", 4.0: "medium",
                 6.9: "medium", 7.0: "high", 8.9: "high", 9.0: "critical", 10: "critical"}
        for score, expected in cases.items():
            self.assertEqual(cvss_to_severity(score), expected, score)

    def test_summary_mentions_devices(self):
        text = format_summary(self.twin)
        self.assertIn("web-01", text)
        self.assertIn("db-01", text)

    def test_build_from_real_file(self):
        twin = build_twin_from_file()
        self.assertGreaterEqual(twin.number_of_nodes(), 1)

    def test_invalid_config_raises(self):
        bad = copy.deepcopy(NETWORK)
        bad["connections"][0]["target"] = "db-99"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_twin_from_file(path)
            self.assertIn("unknown device 'db-99'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
