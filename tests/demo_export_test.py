"""Regression checks for the exported script's verifier-process contract."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


class ExportVerifierTests(unittest.TestCase):
    def test_unrelated_negative_failure_is_not_success(self):
        self.check_script("open tampered-message.json: no such file or directory", False)

    def test_expected_negative_diagnostics_pass(self):
        self.check_script("message mismatch", True)

    def check_script(self, message_diagnostic, expected_success):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = pathlib.Path(__file__).resolve().parents[1] / "src/nativeproof/cmd/lktrs-demo/verify_export.py"
            shutil.copyfile(source, root / "verify.py")
            for number in range(1, 7):
                (root / "reports" / f"{number:02d}").mkdir(parents=True)
            # Only exercise process diagnostics here; these are not proof fixtures.
            verifier = root / "verifier"
            verifier.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                f"  *tampered-message.json*) printf '%s\\n' '{message_diagnostic}' >&2; exit 1;;\n"
                "  *current-policy.json*) printf '%s\\n' 'registry authority scope, epoch, policy or validity mismatch' >&2; exit 1;;\n"
                "  *) printf '%s\\n' '{\"verified\":true}';;\n"
                "esac\n"
            )
            verifier.chmod(0o700)
            result = subprocess.run([sys.executable, str(root / "verify.py"), "--verifier", str(verifier)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode == 0, expected_success, result.stdout + result.stderr)
            if not expected_success:
                self.assertIn(message_diagnostic, result.stderr)
                self.assertNotIn("PASS rejected", result.stdout)


if __name__ == "__main__":
    unittest.main()
