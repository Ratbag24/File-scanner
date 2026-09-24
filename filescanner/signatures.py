"""Known-bad file fingerprints and suspicious byte patterns."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .models import HACKTOOL, HEURISTIC, MALWARE, Finding, Severity

# The EICAR test string is a harmless, industry-standard "fake virus" that every
# antivirus detects. It is stored in two halves so that this source file (and the
# built app) is not itself flagged by other antivirus programs.
_EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_BYTES = _EICAR.encode()

HASH_DB_ENV = "FILESCANNER_HASH_DB"


def default_hash_db_path() -> Path:
    base = os.environ.get("APPDATA") or os.path.join(Path.home(), ".config")
    return Path(base) / "FileScanner" / "bad_hashes.txt"


class HashDatabase:
    """A set of SHA-256 hashes of known malware, one per line in a text file.

    Lines starting with ``#`` are comments. Anything after the hash on a line is
    kept as the malware name, e.g. ``<sha256> Emotet``.
    """

    def __init__(self, entries: dict[str, str] | None = None):
        self.entries: dict[str, str] = dict(entries or {})

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "HashDatabase":
        db = cls()
        candidates = [path] if path else [os.environ.get(HASH_DB_ENV), default_hash_db_path()]
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                db.load_file(candidate)
        return db

    def load_file(self, path: str | os.PathLike) -> None:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.replace(",", " ").split(None, 1)
                digest = parts[0].strip('"').lower()
                if re.fullmatch(r"[0-9a-f]{64}", digest):
                    self.entries[digest] = parts[1].strip() if len(parts) > 1 else "known malware"

    def lookup(self, sha256: str) -> str | None:
        return self.entries.get(sha256.lower())

    def __len__(self) -> int:
        return len(self.entries)


def file_hashes(path: str, chunk_size: int = 1 << 20) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


# Byte patterns that show up in scripts and programs that download or run
# other code in sneaky ways. (pattern, severity, message)
_SCRIPT_PATTERNS = [
    (rb"(?i)powershell(\.exe)?[^\n]{0,80}\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
     Severity.HIGH, "Runs a hidden, encoded PowerShell command"),
    (rb"(?i)(downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer)",
     Severity.MEDIUM, "Downloads files from the internet"),
    (rb"(?i)\b(iex|invoke-expression)\b",
     Severity.MEDIUM, "Runs code built at run time (Invoke-Expression)"),
    (rb"(?i)-(w|windowstyle)\s+hidden",
     Severity.MEDIUM, "Runs in a hidden window"),
    (rb"(?i)set-mppreference\s+-disable|add-mppreference\s+-exclusion",
     Severity.HIGH, "Tries to switch off or bypass Windows Defender"),
    (rb"(?i)vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete",
     Severity.CRITICAL, "Deletes system backups (typical ransomware behaviour)"),
    (rb"(?i)bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no",
     Severity.HIGH, "Disables Windows recovery (typical ransomware behaviour)"),
    (rb"(?i)certutil(\.exe)?\s+-(urlcache|decode)",
     Severity.MEDIUM, "Uses certutil to download or decode files"),
    (rb"(?i)mshta(\.exe)?\s+(http|javascript|vbscript)",
     Severity.HIGH, "Uses mshta to run remote or inline script"),
    (rb"(?i)regsvr32(\.exe)?\s+/s\s+/n\s+/u\s+/i:http",
     Severity.HIGH, "Uses regsvr32 to run a remote script"),
    (rb"(?i)wscript\.shell",
     Severity.LOW, "Can run system commands (WScript.Shell)"),
    (rb"(?i)schtasks(\.exe)?\s+/create",
     Severity.LOW, "Creates a scheduled task (can be used to stay on the computer)"),
    (rb"(?i)currentversion\\run\b",
     Severity.LOW, "Adds itself to Windows start-up"),
    (rb"(?i)(stratum\+tcp://|xmrig|cryptonight|minerd)",
     Severity.HIGH, "Contains cryptocurrency-miner indicators"),
    (rb"(?i)your (personal )?files (have been|are) encrypted",
     Severity.CRITICAL, "Contains a ransomware ransom note"),
]

# Signs of cracks, keygens, cheat engines and credential stealers. These are
# not always viruses, but they are often bundled with them.
_HACKTOOL_PATTERNS = [
    (rb"(?i)\bkeygen\b", "Mentions a key generator (keygen)"),
    (rb"(?i)\b(crack(ed)? by|cracked\.exe|\[crack\])", "Looks like a software crack"),
    (rb"(?i)\b(activator|kms_?pico|kmsauto)\b", "Looks like an illegal licence activator"),
    (rb"(?i)\bloader by\b", "Looks like a crack loader"),
    (rb"(?i)\bpatch(ed)? by\b", "Looks like an unofficial patch"),
    (rb"(?i)\bmimikatz\b|sekurlsa::", "Contains password-stealing tool strings (Mimikatz)"),
    (rb"(?i)\b(dll injector|process hollowing)\b", "Mentions code injection"),
]

_HACKTOOL_NAME = re.compile(
    r"(?i)(keygen|crack|activator|kms[-_ ]?(pico|auto|tools)|cheat|injector|hacktool)"
)


def scan_eicar(data: bytes) -> list[Finding]:
    if EICAR_BYTES in data:
        return [Finding("signature", Severity.CRITICAL,
                        "EICAR antivirus test file (harmless test, detected as a virus by design)",
                        MALWARE)]
    return []


def scan_patterns(data: bytes, is_script: bool, is_program: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, severity, message in _SCRIPT_PATTERNS:
        if re.search(pattern, data):
            # A compiled program can legitimately contain some of these strings,
            # so they count for less outside of scripts.
            sev = severity if is_script else Severity(max(Severity.INFO, severity - 1))
            if not is_script and severity == Severity.CRITICAL:
                sev = Severity.HIGH
            findings.append(Finding("content", sev, message, HEURISTIC))
    # Only code can be a crack or keygen; a document that merely mentions one
    # (a README, a forum post) is not.
    if not (is_script or is_program):
        return findings
    for pattern, message in _HACKTOOL_PATTERNS:
        if re.search(pattern, data):
            findings.append(Finding("hacktool", Severity.MEDIUM, message, HACKTOOL))
    return findings


def scan_name_for_hacktool(name: str, ext: str) -> list[Finding]:
    from .filetypes import EXECUTABLE_EXTS

    if ext in EXECUTABLE_EXTS and _HACKTOOL_NAME.search(os.path.basename(name)):
        return [Finding("hacktool", Severity.MEDIUM,
                        "File name suggests a crack, keygen, cheat or hacking tool", HACKTOOL)]
    return []
