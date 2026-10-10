# SysML modelling workflow

Kagi maintains a standard SysML v2 text model, requirement traceability, a versioned JSON interchange contract, and an adapter that applies model constraints to an actual `kagi-config` topology YAML file. CI checks syntax with the pinned `sysml2` 0.3.1 CLI, validates interchange against JSON Schema Draft 2020-12, and tests adapter behavior.

## Files
- `models/sysml/architecture.sysml`: logical architecture, hard topology minimums, and protection scheme.
- `models/sysml/traceability.json`: requirement-to-code and verification links.
- `schemas/sysml-planner-interchange.schema.json`: version 1.0.0 exchange contract.
- `scripts/validate-sysml.py`: bundle checks and interchange generation.
- `scripts/apply-sysml-constraints.py`: validates interchange and applies constraints to planner YAML.
- `tests/sysml/`: regression tests.
- `.github/workflows/sysml-validation.yml`: pinned syntax checker and CI validation.

## Workflow

```sh
cargo install sysml2 --version 0.3.1 --locked
python -m pip install 'jsonschema==4.25.1' 'PyYAML==6.0.2'
sysml check models/sysml/architecture.sysml
python scripts/validate-sysml.py --revision "$(git rev-parse HEAD)" --output build/sysml-planner-interchange.json
python scripts/apply-sysml-constraints.py \\
  --interchange build/sysml-planner-interchange.json \\
  --input examples/montecarlo-topology.yaml \\
  --output build/kagi-sysml-topology.yaml
kagi-config --config build/kagi-sysml-topology.yaml --output build/kagi.generated.yaml
python -m unittest discover -s tests/sysml -v
```

The adapter preserves topology and existing protection geometry seeds, selects the protection family declared by the model, and enables automatic geometry search so Kagi can choose a feasible geometry for that family. It rejects topologies below the modelled minimum and does not permit the model to weaken Kagi's hard minimum of six hosts and six disks per host.

## Limits and evidence

The pinned `sysml2` checker provides SysML text syntax checking and a bounded requirements-structure profile; it does not claim full OMG semantic conformance. The adapter is an application-specific bridge, not a SysML runtime. Monte Carlo loss probability, placement feasibility, and final geometry remain computed by `kagi-config`. The model intentionally does not claim a numeric durability target without a simulation report and confidence analysis.
