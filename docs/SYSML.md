<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->
# SysML modelling workflow

Kagi checks in a SysML v2 architecture model, traceability map, versioned interchange schema, structural validator, tests, and CI workflow. The local validator is **not** a standards-compliant SysML v2 parser or semantic checker; use a compatible external validator for that purpose.

## Files
- `models/sysml/architecture.sysml`: logical architecture and requirements.
- `models/sysml/traceability.json`: requirement-to-code and verification links.
- `schemas/sysml-planner-interchange.schema.json`: version 1.0.0 exchange contract.
- `scripts/validate-sysml.py`: structural checks and JSON emission.
- `tests/sysml/`: regression tests.
- `.github/workflows/sysml-validation.yml`: CI validation.

## Usage
```sh
python scripts/validate-sysml.py --revision "$(git rev-parse HEAD)" --output build/sysml-planner-interchange.json
python -m unittest discover -s tests/sysml -v
```

An installed validator can be called with `--external-validator`; its command receives the model path as its final argument. Pin and document that tool's version.

The interchange output carries model revision and requirement evidence. Its `constraints` object remains empty until a reviewed mapping to the `kagi-config` schema exists. This prevents unvalidated architecture assumptions becoming operational settings. Durability and placement probabilities remain calculated by `kagi-config`, not asserted by the model.

Structural checks do not prove SysML semantic conformance, durability, or runtime behavior. A follow-up implementation must add a pinned standards-compliant validator and validate the model against it before claiming SysML v2 conformance.
