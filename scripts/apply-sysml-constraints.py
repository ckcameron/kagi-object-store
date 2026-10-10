#!/usr/bin/env python3
"""Apply validated SysML constraints to a Kagi kagi-config topology YAML."""
import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/sysml-planner-interchange.schema.json"


def fail(message):
    print(f"sysml planner adapter error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interchange", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path, help="existing planner topology YAML")
    parser.add_argument("--output", required=True, type=Path, help="merged topology YAML for kagi-config")
    args = parser.parse_args()
    try:
        exchange = json.loads(args.interchange.read_text(encoding="utf-8"))
        config = yaml.safe_load(args.input.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        fail(f"cannot read input document: {exc}")
    errors = sorted(Draft202012Validator(schema).iter_errors(exchange), key=lambda e: list(e.path))
    if errors:
        fail("interchange schema validation failed: " + "; ".join(e.message for e in errors))
    constraints = exchange["constraints"]
    min_hosts = constraints["minimum_hosts"]
    min_disks = constraints["minimum_disks_per_host"]
    scheme = constraints["protection_scheme"]
    if min_hosts < 6 or min_disks < 6:
        fail("model constraints weaken Kagi's hard minimum of 6 hosts and 6 disks per host")
    if not isinstance(config, dict) or not isinstance(config.get("topology"), dict):
        fail("input YAML must contain a topology mapping")
    hosts = config["topology"].get("hosts")
    disks = config["topology"].get("disks")
    if not isinstance(hosts, list) or len(hosts) < min_hosts:
        fail(f"topology has fewer than the SysML minimum of {min_hosts} hosts")
    if not isinstance(disks, list):
        fail("topology.disks must be a list")
    counts = {h.get("name"): 0 for h in hosts if isinstance(h, dict) and isinstance(h.get("name"), str)}
    for disk in disks:
        if isinstance(disk, dict) and disk.get("host") in counts:
            counts[disk["host"]] += 1
    deficient = sorted(name for name, count in counts.items() if count < min_disks)
    if deficient:
        fail(f"hosts below the SysML minimum of {min_disks} disks: {', '.join(deficient)}")
    policies = config.get("policies")
    if not isinstance(policies, dict) or not policies:
        fail("input YAML must define at least one policies entry")
    for name, policy in policies.items():
        if not isinstance(policy, dict):
            fail(f"policy {name!r} must be a mapping")
        protection = policy.setdefault("protection", {})
        if not isinstance(protection, dict):
            fail(f"policy {name!r}.protection must be a mapping")
        protection["type"] = scheme
        optimize = policy.setdefault("optimize", {})
        if not isinstance(optimize, dict):
            fail(f"policy {name!r}.optimize must be a mapping")
        optimize["auto_geometry"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


if __name__ == "__main__":
    main()
