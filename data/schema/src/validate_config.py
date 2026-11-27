import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# تحديد مسار المشروع
PROJECT_DIR = Path(__file__).resolve().parents[3]

# المسارات الافتراضية للملفات
DEFAULT_DATA_FILE = PROJECT_DIR / "data" / "network.json"
DEFAULT_SCHEMA_FILE = PROJECT_DIR / "data" / "schema" / "network.schema.json"


def load_json(path):
    """قراءة ملف JSON وإرجاع محتواه."""
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def format_path(error):
    """تحويل مكان الخطأ إلى شكل مقروء مثل: devices[1].ports[0]"""
    result = ""
    for part in error.absolute_path:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f".{part}" if result else str(part)
    return result or "(root)"


def check_schema(data, schema):
    """المرحلة 1: فحص الشكل والأنواع والحدود (Schema)."""
    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(data),
        key=lambda e: [str(p) for p in e.absolute_path],
    )
    return [f"{format_path(e)}: {e.message}" for e in errors]


def check_references(data):
    """المرحلة 2: فحص العلاقات بين الأجزاء (الـ Schema لا يستطيع فعل ذلك).

    - ID مكرر بين الأجهزة
    - Connection تشير إلى جهاز غير موجود (source / target)
    - Port في الـ Connection غير مفتوح على الجهاز الهدف
    - Service تعمل على Port غير موجود في ports الجهاز، أو Service مكررة على نفس الـ Port
    """
    errors = []
    devices = data["devices"]

    # 1) فحص تكرار الـ IDs وتجميع ports كل جهاز
    first_seen = {}
    ports_by_device = {}
    for index, device in enumerate(devices):
        device_id = device["id"]
        if device_id in first_seen:
            errors.append(
                f"devices[{index}].id: duplicate id '{device_id}' "
                f"(already used at devices[{first_seen[device_id]}])"
            )
        else:
            first_seen[device_id] = index
        ports_by_device.setdefault(device_id, set()).update(device["ports"])

        # فحص الـ services الخاصة بالجهاز
        seen_services = set()
        for s_index, service in enumerate(device["services"]):
            where = f"devices[{index}].services[{s_index}]"
            if service["port"] not in device["ports"]:
                errors.append(
                    f"{where}.port: service '{service['name']}' uses port "
                    f"{service['port']} which is not in the device ports "
                    f"{sorted(device['ports'])}"
                )
            key = (service["port"], service["protocol"])
            if key in seen_services:
                errors.append(
                    f"{where}: duplicate service on {service['protocol']}/{service['port']}"
                )
            seen_services.add(key)

    # 2) فحص الـ Connections
    for index, conn in enumerate(data["connections"]):
        for field in ("source", "target"):
            if conn[field] not in ports_by_device:
                errors.append(
                    f"connections[{index}].{field}: unknown device '{conn[field]}'"
                )

        target = conn["target"]
        if target in ports_by_device and conn["port"] not in ports_by_device[target]:
            errors.append(
                f"connections[{index}].port: port {conn['port']} is not open "
                f"on target '{target}' (open ports: {sorted(ports_by_device[target])})"
            )

    return errors


def validate_data(data, schema):
    """فحص بيانات موجودة في الذاكرة. ترجع (is_valid, errors)."""
    errors = check_schema(data, schema)

    # لو الشكل نفسه غلط لا نكمل الفحص المنطقي، لأن البيانات قد تكون ناقصة
    if not errors:
        errors = check_references(data)

    return (len(errors) == 0, errors)


def validate_config(data_file=DEFAULT_DATA_FILE, schema_file=DEFAULT_SCHEMA_FILE):
    """فحص ملف شبكة كامل. ترجع (is_valid, errors)."""
    network_data = load_json(data_file)
    schema = load_json(schema_file)
    return validate_data(network_data, schema)


def main():
    parser = argparse.ArgumentParser(description="Validate a network config JSON file.")
    parser.add_argument(
        "config",
        nargs="?",
        default=str(DEFAULT_DATA_FILE),
        help="path to the network JSON file (default: data/network.json)",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_FILE),
        help="path to the schema file (default: data/schema/network.schema.json)",
    )
    args = parser.parse_args()

    try:
        is_valid, errors = validate_config(args.config, args.schema)
    except FileNotFoundError as exc:
        print(f"ERROR: file not found: {exc.filename}")
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON syntax: {exc}")
        return 2

    if is_valid:
        print("VALID: Network configuration is correct.")
        return 0

    print(f"INVALID: Network configuration has {len(errors)} error(s).")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
