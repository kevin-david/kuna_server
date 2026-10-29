"""Patch and rollback checks use disposable source files, never Proxmox."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("endpoint_trial", Path(__file__).parents[1] / "scripts/endpoint_trial.py")
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class EndpointTrialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "bridge.py"
        self.original = (Path(__file__).parents[1] / "homeassistant-addon/kuna_server.py").read_bytes()
        self.path.write_bytes(self.original)
        self.expected = hashlib.sha256(self.original).hexdigest()
        self.backup = str(Path(self.directory.name) / "backup.py")
        self.args = SimpleNamespace(port=4555)

    def execute_fixture(self, args, program):
        program = program.replace("Path('/app/kuna_server.py')", f"Path({str(self.path)!r})")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(program, "trial-fixture", "exec"), {})
        return output.getvalue()

    def test_only_selected_port_changes_and_original_is_restored(self):
        with patch.object(trial, "python_in_bridge", self.execute_fixture), patch.object(trial, "restart") as restart:
            candidate_hash = trial.install_trial(self.args, self.expected, self.backup)
            candidate = self.path.read_bytes()
            insertion = b"        if port == 4555:\n            self.ws_url = 'wss://video.kunasystems.com/ws/rtsp/proxy?authtoken='\n"
            self.assertIn(insertion, candidate)
            self.assertEqual(candidate.replace(insertion, b"", 1), self.original)
            self.assertEqual(Path(self.backup).read_bytes(), self.original)
            trial.restore(self.args, self.expected, candidate_hash, self.backup)
            self.assertEqual(self.path.read_bytes(), self.original)
            restart.assert_called_once()

    def test_source_mismatch_prevents_patch(self):
        self.path.write_text("# concurrent source\n")
        with patch.object(trial, "python_in_bridge", self.execute_fixture):
            with self.assertRaises(AssertionError):
                trial.install_trial(self.args, self.expected, self.backup)
        self.assertEqual(self.path.read_text(), "# concurrent source\n")
        self.assertFalse(Path(self.backup).exists())

    def test_rollback_does_not_overwrite_concurrent_source_change(self):
        with patch.object(trial, "python_in_bridge", self.execute_fixture), patch.object(trial, "restart") as restart:
            candidate_hash = trial.install_trial(self.args, self.expected, self.backup)
            self.path.write_text("# independently changed\n")
            with self.assertRaises(AssertionError):
                trial.restore(self.args, self.expected, candidate_hash, self.backup)
            self.assertEqual(self.path.read_text(), "# independently changed\n")
            restart.assert_not_called()

    def test_log_aggregation_excludes_raw_credentials(self):
        logs = """KunaWS[client:1][camera-a] Error ID 1: java.net.ConnectException: Connection refused
KunaWS[client:2][camera-a] session ended (SSLCertVerificationError)
unrelated auth token=private-test-value
"""
        args = SimpleNamespace(container="bridge")
        with patch.object(trial, "guest", return_value=logs):
            counts = trial.log_counts(args, 1000)
        self.assertEqual(counts, {"camera-a": {"connection_refused": 1, "tls_failure": 1}})
        self.assertNotIn("private-test-value", repr(counts))
