import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "scripts/apply-sysml-constraints.py"
VALIDATOR = ROOT / "scripts/validate-sysml.py"


class SysMLIntegrationTests(unittest.TestCase):
    def fixture(self):
        return {
            "schema_version": "1.0.0",
            "model_revision": "test",
            "requirements": [{"id": "REQ-ARCH-001", "title": "Durability", "evidence_status": "requires-run"}],
            "constraints": {"minimum_hosts": 6, "minimum_disks_per_host": 6, "protection_scheme": "clay"},
        }

    def topology(self):
        hosts = [{"name": f"h{i}"} for i in range(6)]
        disks = [{"host": f"h{i}", "id": f"h{i}-d{j}"} for i in range(6) for j in range(6)]
        return {
            "topology": {"hosts": hosts, "disks": disks},
            "policies": {"default": {"protection": {"type": "reed_solomon", "k": 4, "m": 2}}},
        }

    def run_adapter(self, exchange, config):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exchange_path = root / "exchange.json"
            input_path = root / "input.yaml"
            output_path = root / "output.yaml"
            exchange_path.write_text(json.dumps(exchange), encoding="utf-8")
            input_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ADAPTER), "--interchange", str(exchange_path),
                 "--input", str(input_path), "--output", str(output_path)],
                cwd=ROOT, text=True, capture_output=True)
            output = yaml.safe_load(output_path.read_text(encoding="utf-8")) if output_path.exists() else None
            return result, output

    def test_generates_schema_validated_interchange(self):
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--revision", "test-revision"],
            cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["schema_version"], "1.0.0")
        self.assertEqual(data["model_revision"], "test-revision")
        self.assertEqual(data["constraints"]["minimum_hosts"], 6)
        self.assertEqual(data["constraints"]["protection_scheme"], "clay")

    def test_maps_scheme_and_enables_optimizer(self):
        result, output = self.run_adapter(self.fixture(), self.topology())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["policies"]["default"]["protection"]["type"], "clay")
        self.assertTrue(output["policies"]["default"]["optimize"]["auto_geometry"])

    def test_rejects_topology_below_model_minimum(self):
        config = self.topology()
        config["topology"]["hosts"] = config["topology"]["hosts"][:5]
        result, _ = self.run_adapter(self.fixture(), config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fewer than the SysML minimum", result.stderr)

    def test_rejects_weakened_minimum(self):
        exchange = self.fixture()
        exchange["constraints"]["minimum_hosts"] = 5
        result, _ = self.run_adapter(exchange, self.topology())
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
