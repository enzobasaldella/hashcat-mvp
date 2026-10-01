#!/usr/bin/env python3
"""Worker do laboratório sintético: busca tarefas e devolve só status/tempo.

Use AUDIT_API_URL=https://... ou uma porta loopback protegida por túnel SSH.
O token é lido de WORKER_TOKEN; nunca o passe como argumento de linha de comando.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from campaigns import (
    Registration,
    HASHCAT,
    association_paths,
    build_campaigns,
    run_hash_audit,
    validate_environment,
)


class WorkerError(RuntimeError):
    """Falha de configuração ou comunicação, sem dados sensíveis na mensagem."""


class NoRedirect(HTTPRedirectHandler):
    # Não encaminha o token Bearer para um destino indicado por redirecionamento.
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


HTTP = build_opener(NoRedirect)


@dataclass(frozen=True)
class WorkerConfig:
    api_url: str
    token: str


def config_from_environment() -> WorkerConfig:
    api_url = os.environ.get("AUDIT_API_URL", "").rstrip("/")
    token = os.environ.get("WORKER_TOKEN", "")
    parsed = urlsplit(api_url)
    loopback_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if not parsed.netloc or (parsed.scheme != "https" and not loopback_http):
        raise WorkerError("AUDIT_API_URL deve usar HTTPS ou HTTP em loopback por túnel SSH.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise WorkerError("AUDIT_API_URL não pode conter credenciais, consulta ou fragmento.")
    if len(token) < 32:
        raise WorkerError("WORKER_TOKEN ausente ou curto; configure-o no ambiente.")
    return WorkerConfig(api_url=api_url, token=token)


def api_request(config: WorkerConfig, method: str, path: str, payload: dict | None = None) -> dict | None:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        config.api_url + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {config.token}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with HTTP.open(request, timeout=15) as response:
            if response.status == 204:
                return None
            raw = response.read(65537)
            if len(raw) > 65536:
                raise WorkerError("Resposta da API acima do limite esperado.")
            return json.loads(raw)
    except HTTPError as error:
        raise WorkerError(f"API respondeu HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise WorkerError("Não foi possível alcançar a API.") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkerError("A API devolveu um JSON inválido.") from error


def run_job(job: dict) -> dict:
    """Executa as campanhas em pasta temporária e nunca devolve a senha."""
    registration = Registration(
        full_name=job["full_name"],
        institution=job["institution"],
        birth_date=datetime.fromisoformat(job["birth_date"]),
        username=job["username"],
        email=job["email"],
    )
    with tempfile.TemporaryDirectory(prefix="educaseg-worker-") as directory_name:
        directory = Path(directory_name)
        association = association_paths(directory)
        campaigns = build_campaigns(association)
        result = run_hash_audit(
            job["audit_hash"],
            None,
            campaigns,
            directory,
            int(job["job_id"]),
            registration,
            association,
        )
    status = "found" if result.recovered else "error" if result.error else "not_found" if result.completed else "time_limit"
    return {
        "status": status,
        "elapsed_seconds": result.elapsed_seconds,
        "campaign": result.campaign,
    }


def report_result(config: WorkerConfig, job_id: int, result: dict) -> None:
    # Um timeout de rede pode ocorrer depois do commit: a API aceita reenvio idêntico.
    for attempt in range(5):
        try:
            api_request(config, "POST", f"/internal/audit-jobs/{job_id}/result", result)
            return
        except WorkerError:
            if attempt == 4:
                raise
            time.sleep(min(2 ** attempt, 8))


def run_once(config: WorkerConfig) -> bool:
    job = api_request(config, "POST", "/internal/audit-jobs/claim")
    if job is None:
        return False
    job_id = int(job["job_id"])
    started = time.monotonic()
    interrupted = False
    try:
        result = run_job(job)
    except KeyboardInterrupt:
        interrupted = True
        result = {"status": "error", "elapsed_seconds": time.monotonic() - started, "campaign": None}
    except Exception:
        # Não incluir exceções nos logs: podem conter caminhos, hashes ou dados do perfil.
        result = {"status": "error", "elapsed_seconds": time.monotonic() - started, "campaign": None}
    try:
        report_result(config, job_id, result)
    except WorkerError as error:
        raise WorkerError(f"Tarefa {job_id} não teve o resultado confirmado: {error}") from error
    print(f"Tarefa {job_id}: {result['status']} em {result['elapsed_seconds']:.1f} s", flush=True)
    if interrupted:
        raise KeyboardInterrupt
    return True


def validate_runtime() -> None:
    validate_environment()
    try:
        version = subprocess.run(
            [str(HASHCAT), "--version"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkerError("Hashcat não iniciou neste sistema.") from error
    if version.returncode != 0:
        raise WorkerError("Hashcat não iniciou neste sistema.")


def _stop_on_signal(_signum, _frame) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description="Worker das campanhas sintéticas do EducaSeg")
    parser.add_argument("--loop", action="store_true", help="buscar novas tarefas continuamente")
    parser.add_argument("--interval-seconds", type=int, default=5, help="intervalo sem tarefas (padrão: 5)")
    args = parser.parse_args()
    if not 1 <= args.interval_seconds <= 300:
        parser.error("--interval-seconds deve estar entre 1 e 300")

    config = config_from_environment()
    validate_runtime()  # Falha antes de reivindicar uma tarefa se faltar arquivo ou o binário não iniciar.
    signal.signal(signal.SIGTERM, _stop_on_signal)

    try:
        while True:
            if not run_once(config):
                if not args.loop:
                    print("Nenhuma tarefa pendente.")
                    return 0
                time.sleep(args.interval_seconds)
            elif not args.loop:
                return 0
    except KeyboardInterrupt:
        print("Worker interrompido.")
        return 130
    except WorkerError as error:
        print(f"Worker parou: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
