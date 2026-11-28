import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# الملف المتوقع مكانه: <المشروع>/src/benign/benign_traffic.py
PROJECT_DIR = Path(__file__).resolve().parents[2]

# نفس ملف الشبكة اللي الـ Digital Twin بيتبني منه
DEFAULT_NETWORK = PROJECT_DIR / "data" / "network.json"
DEFAULT_OUT = PROJECT_DIR / "data" / "benign" / "benign_traffic_log.csv"

# مستخدمين عاديين من برا الـ twin (مش أجهزة فيه)، بيستخدموا الخدمات المتاحة للعملاء
CLIENTS = ["client-01", "client-02", "client-03", "client-04"]

# شكل الترافيك الطبيعي لكل خدمة: (نطاق زمن الرد ms، نطاق حجم البيانات bytes)
# أي خدمة مش هنا بتاخد DEFAULT_PROFILE
PROFILES = {
    "https": ((10, 60), (500, 5000)),
    "http": ((10, 60), (500, 5000)),
    "ssh": ((5, 40), (200, 2000)),
    "mysql": ((2, 20), (300, 8000)),
}
DEFAULT_PROFILE = ((5, 50), (200, 4000))

# أوزان الاختيار: ترافيك العملاء أكتر من ترافيك الخدمات مع بعض
WEIGHT_CLIENT_FLOW = 3
WEIGHT_SERVICE_FLOW = 2

# نفس أعمدة port_scan_log.csv، لكن "source" بدل "attacker" + عمود label
# أعمدة MITRE فاضية دايمًا: الترافيك الطبيعي مش تكنيك هجوم، فمفيش صف ليه في الكاتالوج
FIELDNAMES = ["timestamp", "scenario", "label", "source", "target",
              "tactic_id", "tactic", "technique_id", "technique", "kill_chain_stage",
              "protocol", "port", "service", "state", "latency_ms", "bytes"]


def load_network(path):
    """يقرا network.json (نفس الملف اللي بيتبني منه الـ twin)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"network file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for key in ("devices", "connections"):
        if key not in data:
            raise ValueError(f"network file is missing '{key}'")
    return data


def service_name(device, port, protocol):
    """اسم الخدمة اللي شغالة على البورت ده في الجهاز، أو unknown."""
    for s in device.get("services", []):
        if s["port"] == port and s["protocol"] == protocol:
            return s["name"]
    return "unknown"


def build_flows(network):
    """يطلّع أنواع الترافيك الطبيعي الممكنة من بيانات الـ twin نفسها.

    1) Connections المعرّفة (مثلاً web-01 -> db-01:3306): ترافيك خدمة لخدمة.
    2) أي جهاز مفيش Connection داخلة عليه: العملاء يوصلوله على خدماته.
       الجهاز اللي عليه Connection داخلة (زي db-01) بيتكلم معاه مصدره بس.
    """
    devices = {d["id"]: d for d in network["devices"]}
    inbound = {c["target"] for c in network["connections"]}
    flows = []

    for conn in network["connections"]:
        target = devices.get(conn["target"])
        if target is None or conn["source"] not in devices:
            raise ValueError(f"connection {conn['source']} -> {conn['target']} "
                             f"refers to an unknown device")
        flows.append({
            "kind": "service_to_service",
            "sources": [conn["source"]],
            "target": conn["target"],
            "port": conn["port"],
            "protocol": conn["protocol"],
            "service": service_name(target, conn["port"], conn["protocol"]),
            "weight": WEIGHT_SERVICE_FLOW,
        })

    for device_id, device in devices.items():
        if device_id in inbound:
            continue
        for s in device.get("services", []):
            flows.append({
                "kind": "client_to_service",
                "sources": CLIENTS,
                "target": device_id,
                "port": s["port"],
                "protocol": s["protocol"],
                "service": s["name"],
                "weight": WEIGHT_CLIENT_FLOW,
            })

    if not flows:
        raise ValueError("no benign flows could be built from this network file")
    return flows


def generate_events(flows, count, start, duration_minutes, seed=None):
    """يولّد أحداث ترافيك طبيعي بتوقيت مختلف لكل حدث. نفس seed يديك نفس النتيجة."""
    rng = random.Random(seed)
    span = duration_minutes * 60
    offsets = sorted(rng.uniform(0, span) for _ in range(count))
    weights = [f["weight"] for f in flows]

    events = []
    for offset in offsets:
        flow = rng.choices(flows, weights=weights, k=1)[0]
        (lat_lo, lat_hi), (b_lo, b_hi) = PROFILES.get(flow["service"], DEFAULT_PROFILE)
        events.append({
            "timestamp": (start + timedelta(seconds=offset)).isoformat(),
            "scenario": "benign_traffic",
            "label": "benign",
            "source": rng.choice(flow["sources"]),
            "target": flow["target"],
            "tactic_id": "",
            "tactic": "",
            "technique_id": "",
            "technique": "",
            "kill_chain_stage": "",
            "protocol": flow["protocol"],
            "port": flow["port"],
            "service": flow["service"],
            "state": "established",
            "latency_ms": rng.randint(lat_lo, lat_hi),
            "bytes": rng.randint(b_lo, b_hi),
        })
    return events


def write_log(path, events):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(events)


def main():
    parser = argparse.ArgumentParser(description="Generate benign (normal) traffic from the network config.")
    parser.add_argument("--network", default=str(DEFAULT_NETWORK), help="path to network.json")
    parser.add_argument("--events", type=int, default=200, help="number of events (default: 200)")
    parser.add_argument("--duration", type=int, default=60, help="time window in minutes (default: 60)")
    parser.add_argument("--start", default=None, help="start time ISO-8601 UTC (default: now)")
    parser.add_argument("--seed", type=int, default=42, help="random seed for repeatability")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="output CSV path")
    args = parser.parse_args()

    if args.events < 1 or args.duration < 1:
        print("Error: --events and --duration must be at least 1", file=sys.stderr)
        return 1

    try:
        start = (datetime.fromisoformat(args.start) if args.start
                 else datetime.now(timezone.utc))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        network = load_network(args.network)
        flows = build_flows(network)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    events = generate_events(flows, args.events, start, args.duration, seed=args.seed)
    write_log(args.out, events)

    print(f"Network: {network.get('network_name', '(unnamed)')}   "
          f"Flow types: {len(flows)}")
    for f in flows:
        n = sum(1 for e in events
                if e["target"] == f["target"] and e["port"] == f["port"]
                and e["source"] in f["sources"])
        print(f"  {f['kind']:<18} {'/'.join(f['sources']) if len(f['sources']) == 1 else 'clients'}"
              f" -> {f['target']}:{f['port']} ({f['service']})  {n} events")
    print(f"Events: {len(events)}   Window: {events[0]['timestamp']}  ->  {events[-1]['timestamp']}")
    print(f"Log written to: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())