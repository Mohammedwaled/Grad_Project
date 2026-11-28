import argparse
import csv
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR / "src"))
from build_twin import build_twin_from_file  # noqa: E402

# اسم الهجوم زي ما هو مكتوب بالظبط في عمود attack_name في الكاتالوج
ATTACK_NAME = "Port Scanning"

# التكنيك اللي السكريبت بينفذه فعلاً: فحص بورتات الجهاز = Network Service Discovery
# (لو بتنفذ فحص تاني زي T1595.001 مرر --technique)
DEFAULT_TECHNIQUE_ID = "T1046"

# مسار الكاتالوج (غيّره لو الملف في مكان تاني، أو مرر --catalog)
DEFAULT_CATALOG = PROJECT_DIR / "attack_api_node" / "out" / "mitre_catalog.csv"
# قايمة بورتات شائعة يجرّبها المهاجم (مش محتاجين نجرّب الـ65535 كلهم)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 3306, 3389, 5900, 8080]


def load_mitre_info(technique_id=DEFAULT_TECHNIQUE_ID,
                    catalog_path=DEFAULT_CATALOG,
                    attack_name=ATTACK_NAME):
    """يقرا بيانات MITRE للتكنيك من mitre_catalog.csv بدل ما تتكتب بإيدينا.

    بيدور على الصف اللي attack_name و attack_technique بتوعه بيطابقوا،
    وبيرجع نفس القيم اللي في الكاتالوج حرفياً عشان D1 يعمل join عليها.
    """
    catalog_path = Path(catalog_path)
    if not catalog_path.exists():
        raise FileNotFoundError(f"MITRE catalog not found: {catalog_path}")

    # utf-8-sig عشان لو الملف محفوظ من Excel بـ BOM ما يبوّظش اسم أول عمود
    with open(catalog_path, newline="", encoding="utf-8-sig") as f:
        rows = [
            {k: (v or "").strip() for k, v in row.items()}
            for row in csv.DictReader(f)
        ]

    family = [r for r in rows if r["attack_name"] == attack_name]
    if not family:
        raise ValueError(f"attack '{attack_name}' not found in {catalog_path.name}")

    for row in family:
        if row["attack_technique"] == technique_id:
            return {
                "attack_name": row["attack_name"],
                "tactic_id": row["tactic_id"],
                "tactic": row["attack_tactic"],
                "technique_id": row["attack_technique"],
                "technique": row["technique_name"],
                "kill_chain_stage": row["kill_chain_stage"],
                # in_lab بتتعلّم TRUE يدوي في الإكسيل بعد ما التكنيك يتنفذ فعلاً
                "in_lab": row["in_lab"].upper() == "TRUE",
            }

    valid = ", ".join(r["attack_technique"] for r in family)
    raise ValueError(
        f"technique '{technique_id}' is not listed under '{attack_name}' "
        f"in the catalog. Valid ids: {valid}"
    )


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


def run_port_scan_scenario(twin, attacker, target, ports=None, seed=None,
                           mitre_info=None):
    """ينفذ سيناريو Port Scanning كامل، ويرجع (سجل الهجوم، تفاصيل كل بورت)."""
    # لو محدش مرر بيانات MITRE، نقراها من الكاتالوج بالتكنيك الافتراضي
    mitre_info = mitre_info or load_mitre_info()

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
        **mitre_info,
    }
    return record, scan_results


def write_scan_log(path, record, scan_results):
    """بيكتب تفاصيل كل بورت في ملف CSV، سطر لكل محاولة."""
    fieldnames = ["timestamp", "scenario", "attacker", "target",
                  "tactic_id", "tactic", "technique_id", "technique",
                  "kill_chain_stage",
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
                "kill_chain_stage": record["kill_chain_stage"],
                "port": r["port"],
                "state": r["state"],
                "latency_ms": r["latency_ms"],
            })


def main():
    parser = argparse.ArgumentParser(description="Run the Port Scanning attack scenario.")
    parser.add_argument("--target", default="web-01", help="device id to scan (default: web-01)")
    parser.add_argument("--attacker", default="external-attacker", help="attacker label")
    parser.add_argument("--seed", type=int, default=42, help="random seed for repeatability")
    parser.add_argument("--technique", default=DEFAULT_TECHNIQUE_ID,
                        help="MITRE technique id from the catalog (default: T1046)")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG),
                        help="path to mitre_catalog.csv")
    parser.add_argument(
        "--out",
        default=str(PROJECT_DIR / "data" / "attacks" / "port_scan_log.csv"),
        help="output CSV path",
    )
    args = parser.parse_args()

    try:
        mitre_info = load_mitre_info(args.technique, args.catalog)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    twin = build_twin_from_file()
    record, scan_results = run_port_scan_scenario(
        twin, args.attacker, args.target, seed=args.seed, mitre_info=mitre_info
    )
    write_scan_log(args.out, record, scan_results)

    print(f"Scenario: {record['scenario']}  (MITRE {record['technique_id']} - {record['technique']})")
    print(f"Tactic: {record['tactic_id']} ({record['tactic']})   Stage: {record['kill_chain_stage']}")
    print(f"Attacker: {record['attacker']}  ->  Target: {record['target']}")
    print(f"Ports scanned: {record['ports_scanned']}   Open ports found: {record['open_ports_found']}")
    print(f"Open ports: {record['open_ports']}")
    print(f"Success: {record['success']}")
    print(f"Log written to: {args.out}")

    if not record["in_lab"]:
        print(f"Note: {record['technique_id']} is not marked in_lab=TRUE in the catalog yet "
              f"(mark it in Excel once the scenario is confirmed).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())