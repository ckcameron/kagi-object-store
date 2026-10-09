#!/usr/bin/env python3
"""Structural validation for Kagi's SysML bundle; not a full SysML parser."""
import argparse, json, re, shlex, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/sysml/architecture.sysml"
TRACE = ROOT / "models/sysml/traceability.json"
SCHEMA = ROOT / "schemas/sysml-planner-interchange.schema.json"

def fail(message):
    print(f"sysml validation error: {message}", file=sys.stderr)
    raise SystemExit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision", default="working-tree")
    parser.add_argument("--external-validator", help="optional SysML v2 validator command")
    args = parser.parse_args()
    for path in (MODEL, TRACE, SCHEMA):
        if not path.is_file():
            fail(f"required file missing: {path.relative_to(ROOT)}")
    model = MODEL.read_text(encoding="utf-8")
    trace = json.loads(TRACE.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    if "package KagiArchitecture" not in model:
        fail("model package KagiArchitecture not found")
    scrubbed = re.sub(r"//[^\n]*|/\*.*?\*/", "", model, flags=re.S)
    depth = 0
    for char in scrubbed:
        depth += (char == "{") - (char == "}")
        if depth < 0:
            fail("unbalanced closing brace in SysML model")
    if depth:
        fail("unbalanced braces in SysML model")
    requirements = trace.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        fail("traceability must contain requirements")
    ids = set()
    for req in requirements:
        rid = req.get("id", "")
        if not re.fullmatch(r"REQ-[A-Z0-9-]+", rid):
            fail(f"invalid requirement ID: {rid!r}")
        if rid in ids:
            fail(f"duplicate requirement ID: {rid}")
        ids.add(rid)
        if not req.get("implementation") or not req.get("verification"):
            fail(f"{rid} must link implementation and verification")
        for rel in req["implementation"]:
            if not (ROOT / rel).exists():
                fail(f"{rid} implementation reference does not exist: {rel}")
    model_ids = set(re.findall(r"requirement\s+<([^>]+)>", model))
    if ids - model_ids:
        fail("traceability IDs absent from model: " + ", ".join(sorted(ids - model_ids)))
    interchange = {
        "schema_version": schema["properties"]["schema_version"]["const"],
        "model_revision": args.revision,
        "requirements": [{"id": r["id"], "title": r["title"], "evidence_status": r["evidence_status"]} for r in requirements],
        "constraints": {}
    }
    if args.external_validator:
        result = subprocess.run(shlex.split(args.external_validator) + [str(MODEL)], cwd=ROOT, check=False)
        if result.returncode:
            fail(f"external SysML validator exited with status {result.returncode}")
    output = json.dumps(interchange, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
