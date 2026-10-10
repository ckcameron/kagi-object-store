#!/usr/bin/env python3
"""Validate Kagi's SysML bundle and emit versioned planner interchange."""
import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/sysml/architecture.sysml"
TRACE = ROOT / "models/sysml/traceability.json"
SCHEMA = ROOT / "schemas/sysml-planner-interchange.schema.json"
SCHEMES = {"replication", "reed_solomon", "lrc", "msr", "clay"}


def fail(message):
    print(f"sysml validation error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision", default="working-tree")
    args = parser.parse_args()
    try:
        model = MODEL.read_text(encoding="utf-8")
        trace = json.loads(TRACE.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read model bundle: {exc}")

    if not re.search(r"\bpackage\s+KagiArchitecture\s*\{", model):
        fail("model package KagiArchitecture not found")
    model_ids = set(re.findall(r"requirement\s+(?:def\s+)?<['\"]?([^>'\"]+)['\"]?>", model))
    requirements = trace.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        fail("traceability must contain a non-empty requirements array")
    seen = set()
    for req in requirements:
        if not isinstance(req, dict):
            fail("each traceability requirement must be an object")
        rid = req.get("id")
        if not isinstance(rid, str) or not re.fullmatch(r"REQ-[A-Z0-9-]+", rid):
            fail(f"invalid requirement ID: {rid!r}")
        if rid in seen:
            fail(f"duplicate requirement ID: {rid}")
        seen.add(rid)
        if rid not in model_ids:
            fail(f"traceability ID absent from SysML model: {rid}")
        for field in ("title", "implementation", "verification", "evidence_status"):
            if field not in req:
                fail(f"{rid} missing traceability field {field}")
        if not req["implementation"] or not req["verification"]:
            fail(f"{rid} must link implementation and verification")
        for rel in req["implementation"]:
            if not isinstance(rel, str) or not (ROOT / rel).exists():
                fail(f"{rid} implementation reference does not exist: {rel}")
    if seen != model_ids:
        fail("untraced SysML requirement IDs: " + ", ".join(sorted(model_ids - seen)))

    def integer_constraint(name):
        match = re.search(rf"attribute\s+{name}\s*:\s*Integer\s*=\s*(\d+)\s*;", model)
        if not match:
            fail(f"missing integer constraint in model: {name}")
        return int(match.group(1))

    match = re.search(r'attribute\s+protectionScheme\s*:\s*String\s*=\s*"([^"]+)"\s*;', model)
    if not match:
        fail("missing protectionScheme string constraint in model")
    scheme = match.group(1)
    if scheme not in SCHEMES:
        fail(f"unsupported protection scheme: {scheme}")
    constraints = {
        "minimum_hosts": integer_constraint("minimumHosts"),
        "minimum_disks_per_host": integer_constraint("minimumDisksPerHost"),
        "protection_scheme": scheme,
    }
    if constraints["minimum_hosts"] < 6 or constraints["minimum_disks_per_host"] < 6:
        fail("model may not weaken Kagi's hard minimum of 6 hosts and 6 disks per host")
    interchange = {
        "schema_version": schema["properties"]["schema_version"]["const"],
        "model_revision": args.revision,
        "requirements": [
            {"id": r["id"], "title": r["title"], "evidence_status": r["evidence_status"]}
            for r in requirements
        ],
        "constraints": constraints,
    }
    errors = sorted(Draft202012Validator(schema).iter_errors(interchange), key=lambda e: list(e.path))
    if errors:
        fail("interchange schema validation failed: " + "; ".join(e.message for e in errors))
    output = json.dumps(interchange, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
