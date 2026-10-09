import json, subprocess, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate-sysml.py"
class SysMLValidationTests(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True)
    def test_emits_versioned_interchange(self):
        r = self.run_tool("--revision", "test-revision")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["schema_version"], "1.0.0")
        self.assertEqual(data["model_revision"], "test-revision")
        self.assertEqual({x["id"] for x in data["requirements"]}, {"REQ-ARCH-001", "REQ-ARCH-002"})
    def test_external_validator_failure_is_reported(self):
        r = self.run_tool("--external-validator", "python -c 'import sys; sys.exit(9)'")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("external SysML validator exited", r.stderr)
if __name__ == "__main__":
    unittest.main()
