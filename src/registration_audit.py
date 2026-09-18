#!/usr/bin/env python3
"""Simula um cadastro e audita várias senhas para o mesmo perfil.

Uso exclusivo no laboratório do MVP. MD5 não deve ser usado para armazenar
senhas em uma aplicação real.
"""

from __future__ import annotations

import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


if getattr(sys, "frozen", False):
    # No pacote portátil, o executável e todos os dados ficam na mesma pasta.
    MVP_ROOT = Path(sys.executable).resolve().parent
    PROJECT_ROOT = MVP_ROOT
    HASHCAT = MVP_ROOT / "hashcat" / "hashcat.bin"
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    MVP_ROOT = PROJECT_ROOT / "hashcat-mvp"
    HASHCAT = PROJECT_ROOT / "hashcat" / "programa" / "hashcat.bin"
WORDLISTS = MVP_ROOT / "wordlists"
RULES = MVP_ROOT / "rules"
MASKS = MVP_ROOT / "masks"
AUDIT_LOG = MVP_ROOT / "audit_log.txt"


@dataclass(frozen=True)
class Registration:
    full_name: str
    institution: str
    birth_date: datetime
    username: str
    email: str


@dataclass(frozen=True)
class Campaign:
    stage: str
    detail: str
    attack_mode: int
    operands: tuple[str, ...]
    extra_arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditResult:
    recovered: bool
    elapsed_seconds: float
    campaign: str | None = None


def configure_terminal_input() -> None:
    """Normaliza o terminal e aceita as sequências comuns de apagamento."""
    if not sys.stdin.isatty():
        return

    try:
        attributes = termios.tcgetattr(sys.stdin.fileno())
        attributes[0] |= termios.ICRNL
        attributes[1] |= termios.OPOST
        attributes[3] |= (
            termios.ICANON
            | termios.ECHO
            | termios.ECHOE
            | termios.ECHOK
            | termios.ISIG
        )
        # DEL é o código enviado pelo Backspace na maioria dos terminais atuais.
        attributes[6][termios.VERASE] = b"\x7f"
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, attributes)
    except termios.error:
        pass

    # GNU Readline cobre tanto Backspace/DEL quanto Ctrl+H e a tecla Delete.
    try:
        import readline

        readline.parse_and_bind(r'"\C-h": backward-delete-char')
        readline.parse_and_bind(r'"\C-?": backward-delete-char')
        readline.parse_and_bind(r'"\e[3~": delete-char')
    except (ImportError, RuntimeError):
        pass


def normalize(value: str) -> str:
    """Remove acentos e deixa somente letras e números minúsculos."""
    decomposed = unicodedata.normalize("NFKD", value)
    without_accents = "".join(
        character
        for character in decomposed
        if not unicodedata.combining(character)
    )
    return "".join(character for character in without_accents.lower() if character.isalnum())


def prompt_nonempty(label: str, minimum: int = 1, maximum: int = 120) -> str:
    while True:
        value = input(label).strip()
        if minimum <= len(value) <= maximum:
            return value
        print(f"Informe entre {minimum} e {maximum} caracteres.")


def prompt_birth_date() -> datetime:
    while True:
        value = input("Data de nascimento (DD/MM/AAAA): ").strip()
        try:
            birth_date = datetime.strptime(value, "%d/%m/%Y")
        except ValueError:
            print("Data inválida. Use DD/MM/AAAA.")
            continue

        if birth_date.date() >= datetime.now().date():
            print("A data precisa estar no passado.")
            continue
        return birth_date


def prompt_username() -> str:
    pattern = re.compile(r"^[A-Za-z0-9._-]{3,30}$")
    while True:
        value = input("Nome de usuário único: ").strip()
        if pattern.fullmatch(value):
            return value
        print("Use de 3 a 30 letras, números, ponto, hífen ou sublinhado.")


def prompt_email() -> str:
    pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    while True:
        value = input("E-mail único: ").strip().lower()
        if len(value) <= 320 and pattern.fullmatch(value):
            return value
        print("E-mail inválido.")


def prompt_password() -> str:
    while True:
        password = input("Senha para testar (máximo de 8 caracteres): ")
        if not 1 <= len(password) <= 8:
            print("A senha deve possuir entre 1 e 8 caracteres.")
            continue
        return password


def prompt_duration_seconds() -> int:
    """Solicita uma quantidade inteira e positiva de segundos."""
    while True:
        raw_value = input("Tempo da auditoria em segundos: ").strip()
        if not raw_value.isdigit():
            print("Digite somente um número inteiro, como 10 ou 500.")
            continue

        seconds = int(raw_value)
        if seconds >= 1:
            return seconds
        print("O tempo precisa ser maior que zero.")


def confirm_registration(registration: Registration) -> bool:
    print("\nCadastro")
    print(f"  Nome: {registration.full_name}")
    print(f"  Instituição: {registration.institution}")
    print(f"  Nascimento: {registration.birth_date.strftime('%d/%m/%Y')}")
    print(f"  Usuário: {registration.username}")
    print(f"  E-mail: {registration.email}")
    answer = input("Confirmar? [s/N]: ").strip().lower()
    return answer in {"s", "sim", "y", "yes"}


def write_candidates(path: Path, candidates: set[str]) -> str:
    clean_candidates = sorted(candidate for candidate in candidates if candidate)
    path.write_text("\n".join(clean_candidates) + "\n", encoding="ascii")
    return str(path)


def case_and_leet_variants(value: str) -> set[str]:
    """Cria variações de caixa e leet que não alteram o comprimento."""
    value = value.lower()
    if not value:
        return set()

    replacements = {
        "a": ("@", "4"),
        "b": ("8",),
        "e": ("3",),
        "g": ("9",),
        "i": ("1",),
        "o": ("0",),
        "s": ("5", "$"),
        "t": ("7",),
    }
    lexical_variants = {value}

    # Uma substituição por vez cobre alterações humanas comuns sem explodir a lista.
    for position, character in enumerate(value):
        for replacement in replacements.get(character, ()):
            lexical_variants.add(value[:position] + replacement + value[position + 1 :])

    # Também inclui uma versão com todas as substituições principais combinadas.
    combined = "".join(replacements.get(character, (character,))[0] for character in value)
    lexical_variants.add(combined)

    variants = set()
    for candidate in lexical_variants:
        variants.update({candidate, candidate.capitalize(), candidate.upper()})
    return variants


def build_association_files(registration: Registration, directory: Path) -> dict[str, str]:
    name_parts = registration.full_name.split()
    name_tokens = {normalize(part) for part in name_parts if normalize(part)}
    first_name = normalize(name_parts[0])
    last_name = normalize(name_parts[-1])
    institution = normalize(registration.institution)
    username = normalize(registration.username)
    email_local = normalize(registration.email.split("@", 1)[0])
    initials = first_name[:1] + last_name[:1]
    birth = registration.birth_date

    bases = name_tokens | {institution, username, email_local, initials}
    date_tokens = {
        birth.strftime("%d"),
        birth.strftime("%m"),
        birth.strftime("%y"),
        birth.strftime("%Y"),
        birth.strftime("%d%m"),
        birth.strftime("%d%m%y"),
    }
    expanded = set(date_tokens)

    # Bases diretas, truncadas e transformadas. A versão capitalizada é essencial
    # para encadear, por exemplo, "Enzo" com uma máscara numérica depois.
    variants_by_size: dict[int, set[str]] = {}
    for maximum in range(1, 9):
        variants = set()
        for base in bases:
            variants.update(case_and_leet_variants(base[:maximum]))
        variants_by_size[maximum] = variants
        expanded.update(variants)

    # Associa bases com informações do nascimento nos dois sentidos.
    for token in date_tokens:
        maximum = 8 - len(token)
        if maximum < 1:
            continue
        for base in variants_by_size[maximum]:
            expanded.add(base + token)
            expanded.add(token + base)

    # Testa pares de campos, com e sem separadores, sempre limitados a oito.
    basic_bases = name_tokens | {institution, username, email_local}
    for left in basic_bases:
        for right in basic_bases:
            if left == right:
                continue
            for separator in ("", ".", "_", "-"):
                joined = left + separator + right
                if len(joined) <= 8:
                    expanded.update(case_and_leet_variants(joined))

    # Encadeia caixa/leet com máscaras numéricas. Isso inclui combinações como
    # "Enzo" + "1592", que uma rule e uma mask isoladas não alcançariam juntas.
    for digit_count in range(1, 5):
        maximum = 8 - digit_count
        for number in range(10**digit_count):
            token = f"{number:0{digit_count}d}"
            for base in variants_by_size[maximum]:
                expanded.add(base + token)
                expanded.add(token + base)

    # Símbolos mais usuais também são combinados com as transformações anteriores.
    for symbol in "!@#$%&*_-.":
        for base in variants_by_size[7]:
            expanded.add(base + symbol)
            expanded.add(symbol + base)

    expanded = {candidate for candidate in expanded if 1 <= len(candidate) <= 8}
    rule_bases = {base[:8] for base in bases if base}
    rule_bases.update(date_tokens)
    combinator_bases = set()
    for base in bases:
        combinator_bases.update(case_and_leet_variants(base[:4]))

    return {
        "expanded": write_candidates(
            directory / "association-expanded.txt",
            expanded,
        ),
        "rule_bases": write_candidates(
            directory / "association-rule-bases.txt",
            rule_bases,
        ),
        "combinator_bases": write_candidates(
            directory / "association-combinator-bases.txt",
            combinator_bases,
        ),
    }


def decode_potfile_value(value: str) -> str:
    if value.startswith("$HEX[") and value.endswith("]"):
        return bytes.fromhex(value[5:-1]).decode("utf-8", errors="replace")
    return value


def recovered_password(potfile: Path, password_hash: str) -> str | None:
    if not potfile.exists():
        return None
    prefix = password_hash + ":"
    for line in potfile.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(prefix):
            return decode_potfile_value(line[len(prefix) :])
    return None


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def execute_campaign(
    campaign: Campaign,
    hash_file: Path,
    potfile: Path,
    deadline: float,
) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 2

    command = [
        str(HASHCAT),
        "-O",
        "-m",
        "0",
        "-a",
        str(campaign.attack_mode),
        str(hash_file),
        *campaign.operands,
        *campaign.extra_arguments,
        "--potfile-path",
        str(potfile),
        "--runtime",
        str(max(1, int(remaining))),
        "--restore-disable",
        "--logfile-disable",
        "--quiet",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=max(0.1, remaining))
    except subprocess.TimeoutExpired:
        stop_process(process)
        return 2
    except KeyboardInterrupt:
        stop_process(process)
        raise


def add_straight(
    campaigns: list[Campaign],
    stage: str,
    detail: str,
    wordlist: str | Path,
    rule: str | Path | None = None,
) -> None:
    extra = ("-r", str(rule)) if rule else ()
    campaigns.append(Campaign(stage, detail, 0, (str(wordlist),), extra))


def build_campaigns(association: dict[str, str]) -> list[Campaign]:
    campaigns: list[Campaign] = []

    # Uma lista já encadeada evita várias inicializações do Hashcat e combina
    # associação, caixa, leet, datas, símbolos e máscaras numéricas.
    add_straight(
        campaigns,
        "Associação expandida",
        "dados pessoais + transformações + números",
        association["expanded"],
    )

    # Como a base pessoal é pequena, podemos aplicar muitas rules sobre ela antes
    # de gastar tempo com as mesmas regras no dicionário brasileiro completo.
    for filename in ("top10_2025.rule", "best66.rule", "leetspeak.rule", "ptbr.rule"):
        add_straight(
            campaigns,
            "Rules essenciais — associação",
            filename,
            association["rule_bases"],
            RULES / "essential" / filename,
        )
    for filename in ("rockyou-30000.rule", "d3ad0ne.rule", "dive.rule"):
        add_straight(
            campaigns,
            "Rules pesadas — associação",
            filename,
            association["rule_bases"],
            RULES / "heavy" / filename,
        )

    # Combina dados pessoais curtos com palavras brasileiras curtas nos dois sentidos.
    short_brazilian_words = WORDLISTS / "by-length/max-4.txt"
    campaigns.append(
        Campaign(
            "Associação + dicionário",
            "dado pessoal seguido de palavra brasileira",
            1,
            (association["combinator_bases"], str(short_brazilian_words)),
        )
    )
    campaigns.append(
        Campaign(
            "Associação + dicionário",
            "palavra brasileira seguida de dado pessoal",
            1,
            (str(short_brazilian_words), association["combinator_bases"]),
        )
    )

    # Wordlist brasileira e regras que respeitam o limite de oito caracteres.
    add_straight(campaigns, "Dicionário brasileiro", "lista direta", WORDLISTS / "br-full-8.txt")
    add_straight(campaigns, "Dicionário brasileiro", "caixa e leet", WORDLISTS / "br-ascii-8.txt", RULES / "max8/01-same-length.rule")
    add_straight(campaigns, "Dicionário brasileiro", "sufixo de um caractere", WORDLISTS / "by-length/max-7.txt", RULES / "max8/02-append-1.rule")
    add_straight(campaigns, "Dicionário brasileiro", "prefixo de um caractere", WORDLISTS / "by-length/max-7.txt", RULES / "max8/03-prepend-1.rule")
    add_straight(campaigns, "Dicionário brasileiro", "associações comuns", WORDLISTS / "by-length/max-7.txt", RULES / "max8/07-association-append.rule")
    add_straight(campaigns, "Dicionário brasileiro", "sufixo de dois dígitos", WORDLISTS / "by-length/max-6.txt", RULES / "max8/04-append-2.rule")
    add_straight(campaigns, "Dicionário brasileiro", "prefixo de dois dígitos", WORDLISTS / "by-length/max-6.txt", RULES / "max8/05-prepend-2.rule")
    add_straight(campaigns, "Dicionário brasileiro", "anos", WORDLISTS / "by-length/max-4.txt", RULES / "max8/06-years-4.rule")

    # Listas opcionais existentes no projeto.
    for filename in ("top100000.txt", "rockyou.txt"):
        path = WORDLISTS / "optional" / filename
        if path.exists():
            add_straight(campaigns, "Listas opcionais", filename, path)

    campaigns.append(Campaign("Máscaras numéricas", "quatro a oito dígitos", 3, (str(MASKS / "01-numeric.hcmask"),)))

    # Formatos frequentes com custo compatível com o teste local.
    for mask in ("?l?l?l?l", "?l?l?l?l?l", "?l?l?l?l?d?d", "?u?l?l?l?d?d"):
        campaigns.append(Campaign("Máscaras comuns", mask, 3, (mask,)))

    # Regras consolidadas. Se consumirem o restante do prazo, o processo é interrompido.
    for filename in ("top10_2025.rule", "best66.rule", "leetspeak.rule", "ptbr.rule"):
        add_straight(
            campaigns,
            "Rules essenciais — BR ASCII",
            filename,
            WORDLISTS / "br-ascii-8.txt",
            RULES / "essential" / filename,
        )
    for filename in ("rockyou-30000.rule", "d3ad0ne.rule", "dive.rule"):
        add_straight(
            campaigns,
            "Rules pesadas — BR ASCII",
            filename,
            WORDLISTS / "br-ascii-8.txt",
            RULES / "heavy" / filename,
        )

    # Última etapa: máscaras amplas usam somente o tempo que ainda estiver disponível.
    campaigns.append(Campaign("Máscaras ampliadas", "formatos comuns completos", 3, (str(MASKS / "02-common-shapes.hcmask"),)))
    campaigns.append(Campaign("Máscaras ampliadas", "alfabéticas pesadas", 3, (str(MASKS / "05-heavy-alpha.hcmask"),)))
    return campaigns


def validate_environment() -> None:
    required = (
        HASHCAT,
        WORDLISTS / "br-full-8.txt",
        WORDLISTS / "br-ascii-8.txt",
        WORDLISTS / "by-length/max-4.txt",
        WORDLISTS / "by-length/max-6.txt",
        WORDLISTS / "by-length/max-7.txt",
        RULES / "max8/01-same-length.rule",
        RULES / "max8/02-append-1.rule",
        RULES / "max8/03-prepend-1.rule",
        RULES / "max8/04-append-2.rule",
        RULES / "max8/05-prepend-2.rule",
        RULES / "max8/06-years-4.rule",
        RULES / "max8/07-association-append.rule",
        RULES / "essential/top10_2025.rule",
        RULES / "essential/best66.rule",
        RULES / "essential/leetspeak.rule",
        RULES / "essential/ptbr.rule",
        RULES / "heavy/rockyou-30000.rule",
        RULES / "heavy/d3ad0ne.rule",
        RULES / "heavy/dive.rule",
        MASKS / "01-numeric.hcmask",
        MASKS / "02-common-shapes.hcmask",
        MASKS / "05-heavy-alpha.hcmask",
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Arquivos necessários não encontrados:\n- " + "\n- ".join(missing))


def start_registration_log(registration: Registration) -> int:
    """Abre uma nova seção no TXT e devolve seu número sequencial."""
    previous_content = ""
    if AUDIT_LOG.exists():
        previous_content = AUDIT_LOG.read_text(encoding="utf-8")

    identifiers = [
        int(match)
        for match in re.findall(r"^Dados do cadastro (\d+)$", previous_content, re.MULTILINE)
    ]
    registration_number = max(identifiers, default=0) + 1

    separator = "\n" if previous_content and not previous_content.endswith("\n\n") else ""
    block = (
        f"{separator}Dados do cadastro {registration_number}\n"
        f"Nome: {registration.full_name}\n"
        f"Instituição: {registration.institution}\n"
        f"Nascimento: {registration.birth_date.strftime('%d/%m/%Y')}\n"
        f"Usuário: {registration.username}\n"
        f"E-mail: {registration.email}\n"
    )
    with AUDIT_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(block)
    AUDIT_LOG.chmod(0o600)
    return registration_number


def append_attempt_log(
    attempt_number: int,
    password: str,
    result: AuditResult,
) -> None:
    """Registra uma tentativa mantendo o formato simples solicitado."""
    if result.recovered:
        status = f"Quebrada em {result.elapsed_seconds:.1f} s"
        if result.campaign:
            status += f" [{result.campaign}]"
    else:
        status = f"Não quebrada em {result.elapsed_seconds:.1f} s"

    with AUDIT_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(f"Senha {attempt_number}: {password} - {status}\n")


def run_single_audit(
    password: str,
    duration_seconds: int,
    campaigns: list[Campaign],
    session_directory: Path,
    attempt_number: int,
) -> AuditResult:
    """Audita uma senha; apenas o MD5 é entregue aos processos do Hashcat."""
    started = time.monotonic()
    deadline = started + duration_seconds
    password_hash = hashlib.md5(
        password.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()

    with tempfile.TemporaryDirectory(
        prefix=f"attempt-{attempt_number:02d}-",
        dir=session_directory,
    ) as attempt_name:
        attempt_directory = Path(attempt_name)
        hash_file = attempt_directory / "target.hash"
        potfile = attempt_directory / "result.potfile"
        hash_file.write_text(password_hash + "\n", encoding="ascii")

        current_stage = None
        errors = 0
        print(f"\nAuditoria iniciada: {duration_seconds} s")

        for campaign in campaigns:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if campaign.stage != current_stage:
                current_stage = campaign.stage
                print(f"  {current_stage} | {int(remaining)} s restantes")

            return_code = execute_campaign(campaign, hash_file, potfile, deadline)
            recovered = recovered_password(potfile, password_hash)
            if recovered is not None:
                elapsed = time.monotonic() - started
                print("\nResultado")
                print(f"  Senha: {recovered}")
                print("  Status: encontrada")
                print(f"  Tempo: {elapsed:.1f} s")
                print(f"  Campanha: {campaign.stage} — {campaign.detail}")
                return AuditResult(
                    recovered=True,
                    elapsed_seconds=elapsed,
                    campaign=f"{campaign.stage} — {campaign.detail}",
                )

            if return_code not in {0, 1, 2, 3, 4}:
                errors += 1

        elapsed = min(time.monotonic() - started, duration_seconds)
        print("\nResultado")
        print(f"  Senha: {password}")
        print("  Status: não encontrada")
        print(f"  Tempo: {elapsed:.1f} s")
        if errors:
            print(f"  Erros operacionais: {errors}")
        return AuditResult(recovered=False, elapsed_seconds=elapsed)


def main() -> int:
    configure_terminal_input()
    print("Registration Audit")
    print("Use somente dados de teste. O log registra senhas em texto claro.\n")

    validate_environment()
    registration = Registration(
        full_name=prompt_nonempty("Nome completo: ", minimum=2),
        institution=prompt_nonempty("Instituição (sigla): ", minimum=2, maximum=20).upper(),
        birth_date=prompt_birth_date(),
        username=prompt_username(),
        email=prompt_email(),
    )

    if not confirm_registration(registration):
        print("Sessão cancelada; nenhum teste foi executado.")
        return 0

    registration_number = start_registration_log(registration)
    print(f"Log: {AUDIT_LOG}")

    with tempfile.TemporaryDirectory(prefix="gt-tecseg-audit-") as temporary_name:
        temporary = Path(temporary_name)
        print("Preparando campanhas...")
        association = build_association_files(registration, temporary)
        campaigns = build_campaigns(association)
        attempt_number = 1

        while True:
            print(f"\nTeste {attempt_number}")
            password = prompt_password()
            duration_seconds = prompt_duration_seconds()
            result = run_single_audit(
                password,
                duration_seconds,
                campaigns,
                temporary,
                attempt_number,
            )
            append_attempt_log(attempt_number, password, result)

            answer = input(
                "\nDeseja testar outra senha com o mesmo cadastro? [s/N]: "
            ).strip().lower()
            if answer not in {"s", "sim", "y", "yes"}:
                break
            attempt_number += 1

    print(f"\nCadastro {registration_number} encerrado.")
    print(f"Log: {AUDIT_LOG}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nTeste cancelado pelo usuário.")
        raise SystemExit(130)
    except (FileNotFoundError, PermissionError) as error:
        print(f"\nErro de configuração: {error}")
        raise SystemExit(1)
