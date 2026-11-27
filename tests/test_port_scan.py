import csv
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(SRC_DIR / "attacks"))

from build_twin import build_twin  # noqa: E402
from port_scan import (  # noqa: E402
    MITRE_INFO,
    run_port_scan_scenario,
    scan_ports,
    write_scan_log,
)

NETWORK = {
    "network_name": "Test-Lab",
    "devices": [
        {
            "id": "web-01",
            "type": "web_server",
            "criticality": "high",
            "ports": [443, 22],
            "services": [{"name": "https", "port": 443, "protocol": "TCP"}],
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


class PortScanTests(unittest.TestCase):
    def setUp(self):
        self.twin = build_twin(NETWORK)

    def test_open_ports_detected(self):
        results = scan_ports(self.twin, "web-01", ports=[22, 443, 3389], seed=1)
        states = {r["port"]: r["state"] for r in results}
        self.assertEqual(states[22], "open")
        self.assertEqual(states[443], "open")
        self.assertEqual(states[3389], "closed")

    def test_unknown_target_raises(self):
        with self.assertRaises(ValueError):
            scan_ports(self.twin, "ghost-01")

    def test_seed_is_repeatable(self):
        r1 = scan_ports(self.twin, "web-01", ports=[22, 443], seed=7)
        r2 = scan_ports(self.twin, "web-01", ports=[22, 443], seed=7)
        self.assertEqual(r1, r2)

    def test_scenario_success_when_port_open(self):
        record, results = run_port_scan_scenario(
            self.twin, "external-attacker", "web-01", seed=1
        )
        self.assertTrue(record["success"])
        self.assertIn(443, record["open_ports"])
        self.assertEqual(record["target"], "web-01")

    def test_scenario_fails_when_no_open_port_in_list(self):
        record, results = run_port_scan_scenario(
            self.twin, "external-attacker", "web-01", ports=[9999], seed=1
        )
        self.assertFalse(record["success"])
        self.assertEqual(record["open_ports"], [])

    def test_mitre_mapping_is_attached(self):
        record, _ = run_port_scan_scenario(self.twin, "attacker", "db-01", seed=1)
        self.assertEqual(record["technique_id"], MITRE_INFO["technique_id"])
        self.assertEqual(record["tactic"], "Discovery")

    def test_csv_log_written_correctly(self):
        record, results = run_port_scan_scenario(
            self.twin, "attacker", "web-01", ports=[22, 443, 3389], seed=1
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "log.csv"
            write_scan_log(out, record, results)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["technique_id"], "T1046")
            ports_in_file = {int(r["port"]) for r in rows}
            self.assertEqual(ports_in_file, {22, 443, 3389})


if __name__ == "__main__":
    unittest.main()