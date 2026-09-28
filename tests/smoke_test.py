#!/usr/bin/env python3
"""Verificação pequena do pacote com hashes e palavras inteiramente sintéticos."""

from __future__ import annotations

import hashlib
import io
import re
import sys
import tempfile
import time
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from registration_audit import (  # noqa: E402
    Campaign,
    HASHCAT,
    MASKS,
    Registration,
    RULES,
    WORDLISTS,
    association_paths,
    build_campaigns,
    execute_campaign,
    recovered_password,
    run_single_audit,
    validate_environment,
)


def check_campaign_files(directory: Path) -> None:
    paths = association_paths(directory)
    for path in paths.values():
        Path(path).write_text("mvp\n", encoding="ascii")

    campaigns = build_campaigns(paths)
    modes = {campaign.attack_mode for campaign in campaigns}
    assert modes == {0, 1, 3, 6, 7}, f"Modos inesperados: {modes}"

    referenced = set()
    for campaign in campaigns:
        for operand in campaign.operands:
            if operand.startswith("/"):
                path = Path(operand)
                assert path.is_file(), f"Arquivo ausente em {campaign.label}: {operand}"
                referenced.add(path)
        if campaign.extra_arguments:
            assert campaign.extra_arguments[0] == "-r"
            path = Path(campaign.extra_arguments[1])
            assert path.is_file()
            referenced.add(path)

    for folder, pattern in ((WORDLISTS, "*.txt"), (RULES, "*.rule"), (MASKS, "*.hcmask")):
        available = set(folder.rglob(pattern))
        assert available <= referenced, f"Arquivos não usados: {sorted(available - referenced)}"

    for mask_file in MASKS.glob("*.hcmask"):
        masks = [line.strip() for line in mask_file.read_text().splitlines() if line.strip()]
        assert masks, mask_file
        assert all(re.fullmatch(r"(?:\?[dlus]){1,8}", mask) for mask in masks), mask_file
    numeric = (MASKS / "01-numeric.hcmask").read_text().splitlines()
    assert numeric == ["?d" * length for length in range(1, 9)]

    for wordlist in WORDLISTS.rglob("*.txt"):
        with wordlist.open(encoding="utf-8") as entries:
            assert all(1 <= len(line.rstrip("\r\n")) <= 8 for line in entries), wordlist
    print(f"OK: {len(campaigns)} campanhas, modos {sorted(modes)}, arquivos presentes")


def check_real_hashcat(directory: Path) -> None:
    base = directory / "base.txt"
    suffix = directory / "suffix.txt"
    base.write_text("mvp\n", encoding="ascii")
    suffix.write_text("7\n", encoding="ascii")

    probes = (
        ("dicionário e rule", Campaign("Teste", "rule", 0, (str(base),), ("-r", str(RULES / "max8/02-append-1.rule"))), "mvp7"),
        ("combinador", Campaign("Teste", "combinador", 1, (str(base), str(suffix))), "mvp7"),
        ("máscara numérica até 8", Campaign("Teste", "máscara", 3, (str(MASKS / "01-numeric.hcmask"),)), "81827718"),
        ("híbrido palavra+mask", Campaign("Teste", "híbrido 6", 6, (str(base), "?d")), "mvp7"),
        ("híbrido mask+palavra", Campaign("Teste", "híbrido 7", 7, ("?d", str(base))), "7mvp"),
        ("híbrido com símbolo", Campaign("Teste", "símbolo", 6, (str(base), "?s")), "mvp!"),
    )

    for number, (label, campaign, password) in enumerate(probes, start=1):
        target = directory / f"target-{number}.hash"
        potfile = directory / f"result-{number}.potfile"
        digest = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
        target.write_text(digest + "\n", encoding="ascii")
        execution = execute_campaign(campaign, target, potfile, time.monotonic() + 120)
        recovered = recovered_password(potfile, digest)
        assert execution.return_code == 0 and not execution.timed_out and recovered == password, (
            f"{label}: saída={execution.return_code}, prazo={execution.timed_out}, "
            f"diagnóstico={execution.diagnostic!r}, recuperada={recovered!r}"
        )
        print(f"OK: {label}")


def check_audit_flow(directory: Path) -> None:
    registration = Registration("Maria Souza", "UFF", datetime(2000, 1, 2), "marias", "maria@example.org")
    association = association_paths(directory)
    campaigns = build_campaigns(association)
    with redirect_stdout(io.StringIO()):
        result = run_single_audit("81827718", 120, campaigns[:3], directory, 1, registration, association)
    assert result.recovered and result.campaign == "Máscaras - numéricas (1 a 8)", result
    print("OK: fluxo completo encontra 81827718 antes das associações")


def main() -> None:
    validate_environment()
    print(f"Hashcat: {HASHCAT}")
    with tempfile.TemporaryDirectory(prefix="gt-tecseg-smoke-") as directory_name:
        directory = Path(directory_name)
        check_campaign_files(directory)
        check_real_hashcat(directory)
        check_audit_flow(directory)
    print("Pacote validado com senhas sintéticas.")


if __name__ == "__main__":
    main()
