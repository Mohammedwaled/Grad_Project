import argparse
import csv
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR / "src"))
from build_twin import build_twin_from_file  # noqa: E402

# معلومات الهجوم المرتبطة برقمه العالمي في MITRE ATT&CK
# (Tactic: Discovery - TA0007, Technique: Network Service Discovery - T1046)
MITRE_INFO = {
    "tactic_id": "TA0007",
    "tactic": "Discovery",
    "technique_id": "T1046",
    "technique": "Network Service Discovery",
}

# قايمة بورتات شائعة يجرّبها المهاجم (مش محتاجين نجرّب الـ65535 كلهم)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 3306, 3389, 5900, 8080]


def scan_ports(twin, target, ports=None, seed=None):
    """يحاكي محاولة المهاجم يفحص بورتات جهاز هدف.

    بيرجع قايمة بكل بورت اتفحص وهل كان مفتوح ولا لأ، بناءً على
    بيانات الـ Digital Twin نفسه (الجهاز ده مش شبكة حقيقية).
    """
    if target not in twin.nodes:
        raise ValueError(f"unknown target device '{target}'")

    ports = sorted(set(ports or COMMON_PORTS))
    open_ports = set(twin.nodes[target]["ports"])

    # seed بيخلي التجربة قابلة للإعادة: نفس الإدخال يديك نفس الأرقام العشوائية
    rng = random.Random(seed)
    results = []
    for port in ports:
        state = "open" if port in open_ports else "closed"
        # زمن رد وهمي بسيط، بورت مفتوح بيرد أبطأ شوية من بورت مقفول
        latency_ms = rng.randint(5, 15) if state == "open" else rng.randint(1, 4)
        results.append({"port": port, "state": state, "latency_ms": latency_ms})

    return results


def run_port_scan_scenario(twin, attacker, target, ports=None, seed=None):
    """ينفذ سيناريو Port Scanning كامل، ويرجع (سجل الهجوم، تفاصيل كل بورت)."""
    started_at = datetime.now(timezone.utc)
    scan_results = scan_ports(twin, target, ports=ports, seed=seed)
    ended_at = datetime.now(timezone.utc)

    open_ports = [r["port"] for r in scan_results if r["state"] == "open"]

    record = {
        "scenario": "port_scanning",
        "attacker": attacker,
        "target": target,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "ports_scanned": len(scan_results),
        "open_ports_found": len(open_ports),
        "open_ports": open_ports,
        # نجح لو لقى بورت واحد مفتوح على الأقل، يعني فيه خدمة يقدر يهاجمها بعدين
        "success": len(open_ports) > 0,
        **MITRE_INFO,
    }
    return record, scan_results


def write_scan_log(path, record, scan_results):
    """بيكتب تفاصيل كل بورت في ملف CSV، سطر لكل محاولة."""
    fieldnames = ["timestamp", "scenario", "attacker", "target",
                  "tactic_id", "tactic", "technique_id", "technique",
                  "port", "state", "latency_ms"]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in scan_results:
            writer.writerow({
                "timestamp": record["started_at"],
                "scenario": record["scenario"],
                "attacker": record["attacker"],
                "target": record["target"],
                "tactic_id": record["tactic_id"],
                "tactic": record["tactic"],
                "technique_id": record["technique_id"],
                "technique": record["technique"],
                "port": r["port"],
                "state": r["state"],
                "latency_ms": r["latency_ms"],
            })


def main():
    parser = argparse.ArgumentParser(description="Run the Port Scanning attack scenario.")
    parser.add_argument("--target", default="web-01", help="device id to scan (default: web-01)")
    parser.add_argument("--attacker", default="external-attacker", help="attacker label")
    parser.add_argument("--seed", type=int, default=42, help="random seed for repeatability")
    parser.add_argument(
        "--out",
        default=str(PROJECT_DIR / "data" / "attacks" / "port_scan_log.csv"),
        help="output CSV path",
    )
    args = parser.parse_args()

    twin = build_twin_from_file()
    record, scan_results = run_port_scan_scenario(
        twin, args.attacker, args.target, seed=args.seed
    )
    write_scan_log(args.out, record, scan_results)

    print(f"Scenario: {record['scenario']}  (MITRE {record['technique_id']} - {record['technique']})")
    print(f"Attacker: {record['attacker']}  ->  Target: {record['target']}")
    print(f"Ports scanned: {record['ports_scanned']}   Open ports found: {record['open_ports_found']}")
    print(f"Open ports: {record['open_ports']}")
    print(f"Success: {record['success']}")
    print(f"Log written to: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())