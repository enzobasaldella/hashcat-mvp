#!/usr/bin/env python3
"""Simula um cadastro e audita várias senhas para o mesmo perfil.

Uso exclusivo no laboratório do MVP. MD5 não deve ser usado para armazenar
senhas em uma aplicação real.
"""

from __future__ import annotations

import hashlib
import math
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
    # O mesmo código pode rodar na pasta de desenvolvimento ou no pacote.
    source_directory = Path(__file__).resolve().parent
    MVP_ROOT = source_directory if (source_directory / "wordlists").is_dir() else source_directory.parent
    PROJECT_ROOT = MVP_ROOT.parent
    bundled_hashcat = MVP_ROOT / "hashcat" / "hashcat.bin"
    HASHCAT = bundled_hashcat if bundled_hashcat.exists() else PROJECT_ROOT / "hashcat" / "programa" / "hashcat.bin"
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
    direct_lookup: bool = False

    @property
    def label(self) -> str:
        return f"{self.stage} - {self.detail}"


@dataclass(frozen=True)
class AuditResult:
    recovered: bool
    elapsed_seconds: float
    campaign: str | None = None
    completed: bool = True
    error: str | None = None


@dataclass(frozen=True)
class CampaignExecution:
    return_code: int | None
    timed_out: bool = False
    diagnostic: str = ""


def format_seconds(value: float) -> str:
    return "<0.1 s" if value < 0.05 else f"{value:.1f} s"


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


def association_paths(directory: Path) -> dict[str, str]:
    return {
        "direct": str(directory / "association-direct.txt"),
        "patterns": str(directory / "association-patterns.txt"),
        "rule_bases": str(directory / "association-rule-bases.txt"),
        "combinator_bases": str(directory / "association-combinator-bases.txt"),
    }


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
    paths = association_paths(directory)
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
    direct = set(date_tokens)
    patterns = set()

    # Bases diretas, truncadas e transformadas. A versão capitalizada é essencial
    # para encadear, por exemplo, "Enzo" com uma máscara numérica depois.
    variants_by_size: dict[int, set[str]] = {}
    for maximum in range(1, 9):
        variants = set()
        for base in bases:
            variants.update(case_and_leet_variants(base[:maximum]))
        variants_by_size[maximum] = variants
        direct.update(variants)

    # Associa bases com informações do nascimento nos dois sentidos.
    for token in date_tokens:
        maximum = 8 - len(token)
        if maximum < 1:
            continue
        for base in variants_by_size[maximum]:
            direct.add(base + token)
            direct.add(token + base)

    # Testa pares de campos, com e sem separadores, sempre limitados a oito.
    basic_bases = name_tokens | {institution, username, email_local}
    for left in basic_bases:
        for right in basic_bases:
            if left == right:
                continue
            for separator in ("", ".", "_", "-"):
                joined = left + separator + right
                if len(joined) <= 8:
                    direct.update(case_and_leet_variants(joined))

    # Encadeia caixa/leet com máscaras numéricas. Isso inclui combinações como
    # "Enzo" + "1592", que uma rule e uma mask isoladas não alcançariam juntas.
    for digit_count in range(1, 5):
        maximum = 8 - digit_count
        for number in range(10**digit_count):
            token = f"{number:0{digit_count}d}"
            for base in variants_by_size[maximum]:
                patterns.add(base + token)
                patterns.add(token + base)

    # Símbolos mais usuais também são combinados com as transformações anteriores.
    for symbol in "!@#$%&*_-.":
        for base in variants_by_size[7]:
            patterns.add(base + symbol)
            patterns.add(symbol + base)

    direct = {candidate for candidate in direct if 1 <= len(candidate) <= 8}
    patterns = {candidate for candidate in patterns if 1 <= len(candidate) <= 8 and candidate not in direct}
    rule_bases = {base[:8] for base in bases if base}
    rule_bases.update(date_tokens)
    combinator_bases = set()
    for base in bases:
        combinator_bases.update(case_and_leet_variants(base[:4]))

    return {
        "direct": write_candidates(
            Path(paths["direct"]),
            direct,
        ),
        "patterns": write_candidates(
            Path(paths["patterns"]),
            patterns,
        ),
        "rule_bases": write_candidates(
            Path(paths["rule_bases"]),
            rule_bases,
        ),
        "combinator_bases": write_candidates(
            Path(paths["combinator_bases"]),
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
) -> CampaignExecution:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return CampaignExecution(None, timed_out=True)

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
        "--restore-disable",
        "--logfile-disable",
        "--quiet",
    ]

    # Guarde o diagnóstico: um arquivo ausente do Hashcat não pode parecer
    # simplesmente uma senha que não foi encontrada.
    with tempfile.TemporaryFile() as diagnostics:
        try:
            process = subprocess.Popen(
                command,
                stdout=diagnostics,
                stderr=diagnostics,
                start_new_session=True,
            )
        except OSError as error:
            return CampaignExecution(None, diagnostic=str(error))

        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            stop_process(process)
            return CampaignExecution(process.returncode, timed_out=True)
        except KeyboardInterrupt:
            stop_process(process)
            raise

        if return_code not in {0, 1}:
            diagnostics.seek(0)
            message = diagnostics.read(2048).decode("utf-8", errors="replace").strip()
            return CampaignExecution(return_code, diagnostic=message or "Hashcat encerrou sem diagnóstico.")
        return CampaignExecution(return_code)


def lookup_wordlist(wordlist: Path, password_hash: str, deadline: float) -> tuple[str | None, bool]:
    """Compara MD5 de uma lista curta sem iniciar outro processo."""
    with wordlist.open("rb") as candidates:
        for index, line in enumerate(candidates):
            if index % 4096 == 0 and time.monotonic() >= deadline:
                return None, False
            candidate = line.rstrip(b"\r\n")
            if candidate and hashlib.md5(candidate, usedforsecurity=False).hexdigest() == password_hash:
                return candidate.decode("utf-8", errors="replace"), True
    return None, True


def add_straight(
    campaigns: list[Campaign],
    stage: str,
    detail: str,
    wordlist: str | Path,
    rule: str | Path | None = None,
    direct_lookup: bool = False,
) -> None:
    extra = ("-r", str(rule)) if rule else ()
    campaigns.append(Campaign(stage, detail, 0, (str(wordlist),), extra, direct_lookup))


def add_hybrid_pair(
    campaigns: list[Campaign],
    wordlist: Path,
    mask: str,
    description: str,
) -> None:
    """Testa palavra+formato e formato+palavra com -a 6 e -a 7."""
    campaigns.append(Campaign("Híbrido BR", f"{description} no final", 6, (str(wordlist), mask)))
    campaigns.append(Campaign("Híbrido BR", f"{description} no início", 7, (mask, str(wordlist))))


def build_campaigns(association: dict[str, str]) -> list[Campaign]:
    campaigns: list[Campaign] = []

    # Candidatos frequentes primeiro; cada acervo é identificado no terminal.
    add_straight(campaigns, "Consulta direta", "Top 100 mil (até 8)", WORDLISTS / "optional/top100000-8.txt", direct_lookup=True)
    add_straight(campaigns, "Consulta direta", "BR completo", WORDLISTS / "br-full-8.txt", direct_lookup=True)
    # A lista numérica é barata em GPU e não precisa virar um TXT gigantesco.
    campaigns.append(Campaign("Máscaras", "numéricas (1 a 8)", 3, (str(MASKS / "01-numeric.hcmask"),)))
    add_straight(campaigns, "Associação", "cadastro + datas + variações", association["direct"])
    # Padrões do cadastro têm bom custo/benefício antes da lista grande.
    add_straight(campaigns, "Associação + padrões", "números e símbolos", association["patterns"])
    add_straight(campaigns, "Consulta direta", "RockYou (até 8)", WORDLISTS / "optional/rockyou-8.txt")
    for filename in ("top10_2025.rule", "best66.rule", "leetspeak.rule", "ptbr.rule"):
        add_straight(
            campaigns,
            "Associação + rules",
            filename,
            association["rule_bases"],
            RULES / "essential" / filename,
        )

    # Duas ordens de combinação entre bases pessoais e palavras brasileiras curtas.
    short_brazilian_words = WORDLISTS / "by-length/max-4.txt"
    campaigns.append(
        Campaign(
            "Associação + BR curto",
            "perfil + palavra",
            1,
            (association["combinator_bases"], str(short_brazilian_words)),
        )
    )
    campaigns.append(
        Campaign(
            "Associação + BR curto",
            "palavra + perfil",
            1,
            (str(short_brazilian_words), association["combinator_bases"]),
        )
    )

    # As três sublistas são usadas: deixam espaço para os caracteres adicionados.
    add_straight(campaigns, "Consulta + rules - BR", "caixa e leet", WORDLISTS / "br-ascii-8.txt", RULES / "max8/01-same-length.rule")
    add_straight(campaigns, "Consulta + rules - BR", "sufixo de 1", WORDLISTS / "by-length/max-7.txt", RULES / "max8/02-append-1.rule")
    add_straight(campaigns, "Consulta + rules - BR", "prefixo de 1", WORDLISTS / "by-length/max-7.txt", RULES / "max8/03-prepend-1.rule")
    add_straight(campaigns, "Consulta + rules - BR", "associações comuns", WORDLISTS / "by-length/max-7.txt", RULES / "max8/07-association-append.rule")
    add_straight(campaigns, "Consulta + rules - BR", "sufixo de 2", WORDLISTS / "by-length/max-6.txt", RULES / "max8/04-append-2.rule")
    add_straight(campaigns, "Consulta + rules - BR", "prefixo de 2", WORDLISTS / "by-length/max-6.txt", RULES / "max8/05-prepend-2.rule")
    add_straight(campaigns, "Consulta + rules - BR", "anos", WORDLISTS / "by-length/max-4.txt", RULES / "max8/06-years-4.rule")

    # Híbridos cobrem palavras brasileiras curtas com números ou símbolos.
    # As sublistas garantem que o candidato final não ultrapasse 8 caracteres.
    add_hybrid_pair(campaigns, WORDLISTS / "by-length/max-7.txt", "?d", "1 dígito")
    add_hybrid_pair(campaigns, WORDLISTS / "by-length/max-6.txt", "?d?d", "2 dígitos")
    add_hybrid_pair(campaigns, WORDLISTS / "by-length/max-4.txt", "?d?d?d?d", "4 dígitos")
    add_hybrid_pair(campaigns, WORDLISTS / "by-length/max-7.txt", "?s", "1 símbolo")

    # Máscaras estruturadas antes das regras sobre listas grandes.
    for mask in ("?l?l?l?l", "?l?l?l?l?l", "?l?l?l?l?d?d", "?u?l?l?l?d?d"):
        campaigns.append(Campaign("Máscaras", mask, 3, (mask,)))

    # No RockYou, só a regra curta é testada antes das regras pesadas.
    add_straight(campaigns, "Consulta + rules - RockYou", "top10_2025.rule", WORDLISTS / "optional/rockyou-8.txt", RULES / "essential/top10_2025.rule")

    for filename in ("rockyou-30000.rule", "d3ad0ne.rule", "dive.rule"):
        add_straight(
            campaigns,
            "Associação + rules pesadas",
            filename,
            association["rule_bases"],
            RULES / "heavy" / filename,
        )

    # Regras consolidadas sobre a lista brasileira maior ficam no fim.
    for filename in ("top10_2025.rule", "best66.rule", "leetspeak.rule", "ptbr.rule"):
        add_straight(
            campaigns,
            "Consulta + rules - BR ASCII",
            filename,
            WORDLISTS / "br-ascii-8.txt",
            RULES / "essential" / filename,
        )
    for filename in ("rockyou-30000.rule", "d3ad0ne.rule", "dive.rule"):
        add_straight(
            campaigns,
            "Consulta + rules pesadas - BR ASCII",
            filename,
            WORDLISTS / "br-ascii-8.txt",
            RULES / "heavy" / filename,
        )

    # Última etapa: máscaras amplas usam somente o tempo que ainda estiver disponível.
    campaigns.append(Campaign("Máscaras amplas", "formatos comuns completos", 3, (str(MASKS / "02-common-shapes.hcmask"),)))
    campaigns.append(Campaign("Máscaras amplas", "alfabéticas pesadas", 3, (str(MASKS / "05-heavy-alpha.hcmask"),)))
    return campaigns


def validate_environment() -> None:
    required = (
        HASHCAT,
        HASHCAT.parent / "hashcat.hcstat2",
        HASHCAT.parent / "OpenCL/markov_le.cl",
        HASHCAT.parent / "OpenCL/markov_be.cl",
        WORDLISTS / "optional/top100000-8.txt",
        WORDLISTS / "optional/rockyou-8.txt",
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
        status = f"Quebrada em {format_seconds(result.elapsed_seconds)}"
        if result.campaign:
            status += f" [{result.campaign}]"
    elif result.error:
        status = f"Erro operacional em {format_seconds(result.elapsed_seconds)} [{result.campaign}]"
    elif not result.completed:
        status = f"Tempo esgotado em {format_seconds(result.elapsed_seconds)} (teste parcial)"
    else:
        status = f"Não quebrada após todas as campanhas em {format_seconds(result.elapsed_seconds)}"

    with AUDIT_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(f"Senha {attempt_number}: {password} - {status}\n")


def run_single_audit(
    password: str,
    duration_seconds: int,
    campaigns: list[Campaign],
    session_directory: Path,
    attempt_number: int,
    registration: Registration,
    association: dict[str, str],
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

        print(f"\nAuditoria iniciada: {duration_seconds} s")
        completed = False

        for index, campaign in enumerate(campaigns, start=1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            print(
                f"  [{index:02d}/{len(campaigns):02d}] {campaign.label} | {math.ceil(remaining)} s restantes",
                flush=True,
            )

            campaign_started = time.monotonic()
            if campaign.stage == "Associação" and not Path(association["direct"]).exists():
                print("           preparando associações do cadastro...", flush=True)
                build_association_files(registration, session_directory)
            if campaign.direct_lookup:
                recovered, lookup_completed = lookup_wordlist(Path(campaign.operands[0]), password_hash, deadline)
                execution = CampaignExecution(0 if recovered is not None else 1, timed_out=not lookup_completed)
            else:
                execution = execute_campaign(campaign, hash_file, potfile, deadline)
                recovered = recovered_password(potfile, password_hash)
            campaign_elapsed = time.monotonic() - campaign_started
            if recovered is not None:
                elapsed = time.monotonic() - started
                print(f"           encontrada em {format_seconds(campaign_elapsed)}")
                print("\nResultado")
                print(f"  Senha: {recovered}")
                print("  Status: encontrada")
                print(f"  Tempo: {format_seconds(elapsed)}")
                print(f"  Campanha: {campaign.label}")
                return AuditResult(
                    recovered=True,
                    elapsed_seconds=elapsed,
                    campaign=campaign.label,
                )

            if execution.diagnostic or (not execution.timed_out and execution.return_code != 1):
                diagnostic = execution.diagnostic or f"Código de saída inesperado: {execution.return_code}"
                print(f"           ERRO após {format_seconds(campaign_elapsed)}: {diagnostic}")
                print("\nResultado")
                print("  Status: auditoria interrompida por erro operacional")
                print(f"  Campanha: {campaign.label}")
                return AuditResult(False, time.monotonic() - started, campaign.label, completed=False, error=diagnostic)
            if execution.timed_out:
                print(f"           prazo atingido após {format_seconds(campaign_elapsed)}")
                break
            print(f"           concluída sem encontrar em {format_seconds(campaign_elapsed)}")
        else:
            completed = True

        elapsed = min(time.monotonic() - started, duration_seconds)
        print("\nResultado")
        print(f"  Senha: {password}")
        print("  Status: não encontrada após todas as campanhas" if completed else "  Status: tempo esgotado; teste parcial")
        print(f"  Tempo: {format_seconds(elapsed)}")
        return AuditResult(recovered=False, elapsed_seconds=elapsed, completed=completed)


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
        association = association_paths(temporary)
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
                registration,
                association,
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
