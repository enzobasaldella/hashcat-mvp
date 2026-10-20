"""Testes rápidos do worker, sem GPU, rede ou dados reais."""

import hashlib
import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from audit_worker import WorkerConfig, WorkerError, config_from_environment, run_once  # noqa: E402
from campaigns import Campaign, Registration, association_paths, build_campaigns, execute_campaign, run_hash_audit  # noqa: E402


class WorkerTests(unittest.TestCase):
    def test_hashcat_receives_remaining_runtime(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            campaign = Campaign("Teste", "máscara", 3, ("?d",))
            with patch("campaigns.subprocess.Popen") as process:
                process.return_value.wait.return_value = 1
                result = execute_campaign(
                    campaign, directory / "target.hash", directory / "result.potfile", time.monotonic() + 5.2
                )
            command = process.call_args.args[0]
            self.assertEqual(command[command.index("--runtime") + 1], "6")
            self.assertEqual(result.return_code, 1)

    def test_priority_order_preserves_fast_and_personal_stages(self):
        with tempfile.TemporaryDirectory() as directory_name:
            labels = [campaign.label for campaign in build_campaigns(association_paths(Path(directory_name)))]
        self.assertEqual(labels[:4], [
            "Consulta direta - Top 100 mil (até 8)",
            "Consulta direta - BR completo",
            "Consulta direta - RockYou (até 8)",
            "Associação - cadastro + datas + variações",
        ])
        self.assertGreater(
            labels.index("Máscaras - numéricas (1 a 8)"),
            labels.index("Associação + BR curto - palavra + perfil"),
        )

    def test_hash_only_audit_does_not_print_password(self):
        password = "Azul123"
        digest = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
        registration = Registration("Maria Souza", "UFF", datetime(2000, 1, 2), "marias", "maria@example.org")
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            wordlist = directory / "candidates.txt"
            wordlist.write_text("outra\nAzul123\n", encoding="utf-8")
            campaign = Campaign("Consulta direta", "teste", 0, (str(wordlist),), direct_lookup=True)
            output = io.StringIO()
            with redirect_stdout(output):
                result = run_hash_audit(
                    digest, 10, [campaign], directory, 1, registration, association_paths(directory)
                )
            self.assertTrue(result.recovered)
            self.assertEqual(result.campaign, "Consulta direta - teste")
            self.assertNotIn(password, output.getvalue())
            self.assertEqual(list(directory.glob("*.potfile")), [])

    def test_campaign_progress_callback(self):
        digest = hashlib.md5(b"Azul123", usedforsecurity=False).hexdigest()
        registration = Registration("Maria Souza", "UFF", datetime(2000, 1, 2), "marias", "maria@example.org")
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            wordlist = directory / "candidates.txt"
            wordlist.write_text("Azul123\n", encoding="utf-8")
            campaign = Campaign("Consulta direta", "teste", 0, (str(wordlist),), direct_lookup=True)
            updates = []
            result = run_hash_audit(
                digest, None, [campaign], directory, 1, registration, association_paths(directory),
                on_campaign=lambda index, total, label, finished: updates.append((index, total, label, finished)),
            )
        self.assertTrue(result.recovered)
        self.assertEqual(updates, [(1, 1, campaign.label, False), (1, 1, campaign.label, True)])

    def test_worker_reports_only_status_time_and_campaign(self):
        job = {"job_id": 7, "audit_hash": "0" * 32, "full_name": "Pessoa Sintética"}
        result = {"status": "found", "elapsed_seconds": 1.2, "campaign": "Teste sintético"}
        config = WorkerConfig("http://127.0.0.1:18000", "x" * 32)
        output = io.StringIO()
        with patch("audit_worker.api_request", side_effect=[job, {}]) as request, patch(
            "audit_worker.run_job", return_value=result
        ), redirect_stdout(output):
            self.assertTrue(run_once(config))
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[1].args[3], result)
        self.assertNotIn(job["audit_hash"], output.getvalue())
        self.assertNotIn(job["full_name"], output.getvalue())

    def test_plain_http_is_limited_to_loopback(self):
        with patch.dict(os.environ, {"AUDIT_API_URL": "http://example.org", "WORKER_TOKEN": "x" * 32}):
            with self.assertRaises(WorkerError):
                config_from_environment()
        with patch.dict(os.environ, {"AUDIT_API_URL": "http://127.0.0.1:18000", "WORKER_TOKEN": "x" * 32}):
            self.assertEqual(config_from_environment().api_url, "http://127.0.0.1:18000")

    def test_without_deadline_finishes_after_last_campaign(self):
        digest = hashlib.md5(b"nada", usedforsecurity=False).hexdigest()
        registration = Registration("Maria Souza", "UFF", datetime(2000, 1, 2), "marias", "maria@example.org")
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            wordlist = directory / "candidates.txt"
            wordlist.write_text("outra\n", encoding="utf-8")
            campaign = Campaign("Consulta direta", "teste", 0, (str(wordlist),), direct_lookup=True)
            result = run_hash_audit(digest, None, [campaign, campaign], directory, 1, registration, association_paths(directory))
            self.assertFalse(result.recovered)
            self.assertTrue(result.completed)
            self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
