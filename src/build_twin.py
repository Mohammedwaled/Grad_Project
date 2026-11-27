import argparse
import json
import sys
from pathlib import Path

import networkx as nx

PROJECT_DIR = Path(__file__).resolve().parents[1]

# استيراد الـ Validator من فولدر data/schema/src
sys.path.insert(0, str(PROJECT_DIR / "data" / "schema" / "src"))
from validate_config import (  # noqa: E402
    DEFAULT_DATA_FILE,
    DEFAULT_SCHEMA_FILE,
    load_json,
    validate_data,
)

# 4 مستويات أهمية للأصول، ولكل مستوى رقم نقدر نحسب به لاحقًا (Risk / Path Ranking)
CRITICALITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def cvss_to_severity(score):
    """تحويل رقم CVSS (0-10) إلى تصنيف الخطورة حسب معيار CVSS v3."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def build_twin(data):
    """بناء الـ Digital Twin كـ Graph من بيانات شبكة سليمة (بعد الـ Validation).

    - كل جهاز = Node
    - كل Connection = Edge (اتجاه من source إلى target)
    نستخدم MultiDiGraph لأن ممكن جهازين يكون بينهم أكتر من Connection على Ports مختلفة.
    """
    twin = nx.MultiDiGraph(name=data["network_name"])

    for device in data["devices"]:
        services = []
        vulnerabilities = []

        for service in device["services"]:
            services.append(
                {
                    "name": service["name"],
                    "port": service["port"],
                    "protocol": service["protocol"],
                    "version": service.get("version"),
                }
            )
            # ربط كل ثغرة بالخدمة اللي فيها (جهاز <- خدمة <- ثغرة)
            for vuln in service.get("vulnerabilities", []):
                vulnerabilities.append(
                    {
                        "id": vuln["id"],
                        "cvss": vuln["cvss"],
                        "severity": cvss_to_severity(vuln["cvss"]),
                        "service": service["name"],
                        "port": service["port"],
                        "description": vuln.get("description", ""),
                    }
                )

        twin.add_node(
            device["id"],
            type=device["type"],
            criticality=device["criticality"],
            criticality_score=CRITICALITY_SCORE[device["criticality"]],
            ports=sorted(device["ports"]),
            services=services,
            vulnerabilities=vulnerabilities,
            max_cvss=max((v["cvss"] for v in vulnerabilities), default=0.0),
        )

    for conn in data["connections"]:
        twin.add_edge(
            conn["source"],
            conn["target"],
            port=conn["port"],
            protocol=conn["protocol"],
        )

    return twin


def build_twin_from_file(data_file=DEFAULT_DATA_FILE, schema_file=DEFAULT_SCHEMA_FILE):
    """قراءة الملف + فحصه + بناء الـ Twin. لو الملف غلط نرمي ValueError بالأخطاء."""
    data = load_json(data_file)
    schema = load_json(schema_file)

    is_valid, errors = validate_data(data, schema)
    if not is_valid:
        raise ValueError("Invalid network configuration:\n- " + "\n- ".join(errors))

    return build_twin(data)


def format_summary(twin):
    """ملخص نصي للـ Twin للطباعة."""
    lines = [
        f"Digital Twin: {twin.graph['name']} "
        f"({twin.number_of_nodes()} devices, {twin.number_of_edges()} connections)",
        "",
        "DEVICES",
    ]

    for node, attrs in twin.nodes(data=True):
        max_cvss = attrs["max_cvss"]
        severity = cvss_to_severity(max_cvss)
        lines.append(
            f"  {node:<10} {attrs['type']:<20} "
            f"criticality={attrs['criticality']}({attrs['criticality_score']})  "
            f"services={len(attrs['services'])}  "
            f"vulns={len(attrs['vulnerabilities'])}  "
            f"max_cvss={max_cvss} ({severity})"
        )

    lines += ["", "CONNECTIONS"]
    for source, target, attrs in twin.edges(data=True):
        lines.append(f"  {source} --{attrs['protocol']}/{attrs['port']}--> {target}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Build the digital twin graph.")
    parser.add_argument(
        "config",
        nargs="?",
        default=str(DEFAULT_DATA_FILE),
        help="path to the network JSON file (default: data/network.json)",
    )
    args = parser.parse_args()

    try:
        twin = build_twin_from_file(args.config)
    except ValueError as exc:
        print(f"INVALID: {exc}")
        return 1
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 2

    print(format_summary(twin))
    return 0


if __name__ == "__main__":
    sys.exit(main())
