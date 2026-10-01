"""Campanhas de auditoria para contas inteiramente fictícias do laboratório."""

from __future__ import annotations

import hashlib
import math
import os
import re
import signal
import subprocess
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


MVP_ROOT = Path(__file__).resolve().parent.parent
HASHCAT = MVP_ROOT / "hashcat" / "hashcat.bin"
WORDLISTS = MVP_ROOT / "wordlists"
RULES = MVP_ROOT / "rules"
MASKS = MVP_ROOT / "masks"
COMMON_SYMBOLS = "!@#._-"


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


def normalize(value: str) -> str:
    """Remove acentos e deixa somente letras e números minúsculos."""
    decomposed = unicodedata.normalize("NFKD", value)
    without_accents = "".join(
        character
        for character in decomposed
        if not unicodedata.combining(character)
    )
    return "".join(character for character in without_accents.lower() if character.isalnum())


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
        "hybrid_3": str(directory / "hybrid-bases-max-3.txt"),
        "hybrid_4": str(directory / "hybrid-bases-max-4.txt"),
        "hybrid_5": str(directory / "hybrid-bases-max-5.txt"),
        "year_symbol_rules": str(directory / "year-symbol.rule"),
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

    # Uma base curta permite combinar números e símbolo sem ultrapassar 8.
    short_brazilian_words = set((WORDLISTS / "by-length/max-6.txt").read_text(encoding="ascii").splitlines())
    hybrid_bases = {}
    for maximum in (3, 4, 5):
        candidates = {word for word in short_brazilian_words if 1 <= len(word) <= maximum}
        candidates.update(base for base in variants_by_size[maximum] if 1 <= len(base) <= maximum)
        hybrid_bases[maximum] = write_candidates(Path(paths[f"hybrid_{maximum}"]), candidates)

    # Rules compostas: a saída de uma campanha não alimenta outra campanha.
    # Portanto, ano e símbolo precisam aparecer juntos na mesma regra.
    years = set(range(datetime.now().year - 3, datetime.now().year + 2)) | {birth.year}
    year_symbol_rules = []
    for year in sorted(years):
        append_year = "".join(f"${digit}" for digit in f"{year:04d}")
        for symbol in COMMON_SYMBOLS:
            append_symbol = f"${symbol}"
            year_symbol_rules.extend((append_year + append_symbol, append_symbol + append_year))
    Path(paths["year_symbol_rules"]).write_text("\n".join(year_symbol_rules) + "\n", encoding="ascii")

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
        "hybrid_3": hybrid_bases[3],
        "hybrid_4": hybrid_bases[4],
        "hybrid_5": hybrid_bases[5],
        "year_symbol_rules": paths["year_symbol_rules"],
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
    deadline: float | None,
) -> CampaignExecution:
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
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


def lookup_wordlist(wordlist: Path, password_hash: str, deadline: float | None) -> tuple[str | None, bool]:
    """Compara MD5 de uma lista curta sem iniciar outro processo."""
    with wordlist.open("rb") as candidates:
        for index, line in enumerate(candidates):
            if deadline is not None and index % 4096 == 0 and time.monotonic() >= deadline:
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
    add_straight(
        campaigns,
        "Associação + ano/símbolo",
        "base curta + ano plausível + símbolo",
        association["hybrid_3"],
        association["year_symbol_rules"],
    )
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

    # Seis formatos gerais: base até 3/4/5 + números + símbolo, nas duas ordens.
    for maximum, digit_count in ((3, 4), (4, 3), (5, 2)):
        base_file = association[f"hybrid_{maximum}"]
        digits = "?d" * digit_count
        for mask, order in ((digits + "?1", "números + símbolo"), ("?1" + digits, "símbolo + números")):
            campaigns.append(
                Campaign(
                    "Híbrido base curta",
                    f"base até {maximum} + {order}",
                    6,
                    (base_file, mask),
                    ("-1", COMMON_SYMBOLS),
                )
            )

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


def run_hash_audit(
    password_hash: str,
    duration_seconds: int | None,
    campaigns: list[Campaign],
    session_directory: Path,
    attempt_number: int,
    registration: Registration,
    association: dict[str, str],
    *,
    progress: bool = False,
) -> AuditResult:
    """Executa as campanhas usando somente o MD5; não registra a senha recuperada."""
    if not re.fullmatch(r"[0-9a-fA-F]{32}", password_hash):
        raise ValueError("Hash MD5 inválido para o laboratório.")
    if duration_seconds is not None and duration_seconds < 1:
        raise ValueError("O prazo precisa ser positivo.")
    password_hash = password_hash.lower()

    def announce(message: str) -> None:
        if progress:
            print(message, flush=True)

    started = time.monotonic()
    deadline = started + duration_seconds if duration_seconds is not None else None

    with tempfile.TemporaryDirectory(
        prefix=f"attempt-{attempt_number:02d}-",
        dir=session_directory,
    ) as attempt_name:
        attempt_directory = Path(attempt_name)
        hash_file = attempt_directory / "target.hash"
        potfile = attempt_directory / "result.potfile"
        hash_file.write_text(password_hash + "\n", encoding="ascii")

        announce(f"\nAuditoria iniciada: {duration_seconds} s" if duration_seconds is not None else "\nAuditoria iniciada: todas as campanhas")
        completed = False

        for index, campaign in enumerate(campaigns, start=1):
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                break
            suffix = f" | {math.ceil(remaining)} s restantes" if remaining is not None else ""
            announce(f"  [{index:02d}/{len(campaigns):02d}] {campaign.label}{suffix}")

            campaign_started = time.monotonic()
            if campaign.stage == "Associação" and not Path(association["direct"]).exists():
                announce("           preparando associações do cadastro...")
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
                announce(f"           encontrada em {format_seconds(campaign_elapsed)}")
                return AuditResult(
                    recovered=True,
                    elapsed_seconds=elapsed,
                    campaign=campaign.label,
                )

            if execution.diagnostic or (not execution.timed_out and execution.return_code != 1):
                diagnostic = execution.diagnostic or f"Código de saída inesperado: {execution.return_code}"
                announce(f"           ERRO após {format_seconds(campaign_elapsed)}: {diagnostic}")
                return AuditResult(False, time.monotonic() - started, campaign.label, completed=False, error=diagnostic)
            if execution.timed_out:
                announce(f"           prazo atingido após {format_seconds(campaign_elapsed)}")
                break
            announce(f"           concluída sem encontrar em {format_seconds(campaign_elapsed)}")
        else:
            completed = True

        elapsed = time.monotonic() - started
        if duration_seconds is not None:
            elapsed = min(elapsed, duration_seconds)
        return AuditResult(recovered=False, elapsed_seconds=elapsed, completed=completed)
