"""The scanning engine: runs every check on a file and combines the results."""

from __future__ import annotations

import hashlib
import io
import os
import threading
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from . import documents, pe, torrent
from .engines import ClamAV, YaraRules, virustotal_lookup
from .filetypes import (ARCHIVE_EXTS, EXECUTABLE_EXTS, detect_type, double_extension,
                        extension, extension_mismatch, has_hidden_characters)
from .models import INFO, Finding, ScanResult, Severity
from .signatures import (HashDatabase, file_hashes, scan_eicar, scan_name_for_hacktool,
                         scan_patterns)

MAX_CONTENT_BYTES = 200 * 1024 * 1024   # larger files are hashed but not read into memory
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_TOTAL = 1024 * 1024 * 1024  # stop unpacking after 1 GB (zip-bomb protection)

SCRIPT_EXTS = {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
               ".wsh", ".hta", ".sh", ".py", ".reg", ".scf", ".inf"}
OFFICE_EXTS = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb",
               ".xlt", ".xltm", ".ppt", ".pptx", ".pptm", ".potm", ".ppsm"}


@dataclass
class ScanOptions:
    use_clamav: bool = True
    clamav_path: str | None = None
    use_yara: bool = True
    virustotal_key: str | None = None
    hash_db_path: str | None = None
    scan_archives: bool = True
    extra_rules_dir: str | None = None


@dataclass
class Scanner:
    options: ScanOptions = field(default_factory=ScanOptions)

    def __post_init__(self):
        self.hash_db = HashDatabase.load(self.options.hash_db_path)
        self.clamav = ClamAV(self.options.clamav_path) if self.options.use_clamav else None
        self.yara = YaraRules(self.options.extra_rules_dir) if self.options.use_yara else None

    def engine_status(self) -> dict[str, str]:
        from .pe import pefile
        from .documents import VBA_Parser

        return {
            "Built-in checks": "on",
            "Known-malware hash list": f"{len(self.hash_db)} fingerprints" if len(self.hash_db) else "empty",
            "ClamAV": (f"on ({self.clamav.binary})" if self.clamav and self.clamav.available
                       else "off" if not self.options.use_clamav else "not found"),
            "YARA rules": ("on" if self.yara and self.yara.available
                           else (f"error: {self.yara.error}" if self.yara and self.yara.error else "off")),
            "Program analysis (pefile)": "on" if pefile else "basic",
            "Macro analysis (oletools)": "on" if VBA_Parser else "basic",
            "VirusTotal": "on" if (self.options.virustotal_key or os.environ.get("VT_API_KEY")) else "no API key",
        }

    # ------------------------------------------------------------------ walking

    def iter_files(self, paths: list[str]) -> Iterator[str]:
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    dirs.sort()
                    for name in sorted(files):
                        yield os.path.join(root, name)
            else:
                yield path

    def scan_paths(self, paths: list[str], progress: Callable[[str], None] | None = None,
                   cancel: threading.Event | None = None) -> Iterator[ScanResult]:
        for path in self.iter_files(paths):
            if cancel is not None and cancel.is_set():
                return
            if progress:
                progress(path)
            yield self.scan_file(path)

    # ----------------------------------------------------------------- one file

    def scan_file(self, path: str) -> ScanResult:
        result = ScanResult(path=path)
        try:
            result.size = os.path.getsize(path)
            hashes = file_hashes(path)
            result.sha256 = hashes["sha256"]
            data = b""
            if result.size <= MAX_CONTENT_BYTES:
                with open(path, "rb") as fh:
                    data = fh.read()
            else:
                result.findings.append(Finding("size", Severity.INFO,
                                               "File is very large; only its fingerprint and name were checked",
                                               INFO))
                with open(path, "rb") as fh:
                    data = fh.read(64 * 1024)
            result.findings.extend(self._analyse(os.path.basename(path), data, result.sha256, depth=0,
                                                 full=result.size <= MAX_CONTENT_BYTES))
            if self.clamav and self.clamav.available:
                result.findings.extend(self.clamav.scan(path))
            result.findings.extend(virustotal_lookup(result.sha256, self.options.virustotal_key))
        except (OSError, MemoryError) as exc:
            result.error = str(exc)
        result.findings = _dedupe(result.findings)
        result.findings.sort(key=lambda f: f.severity, reverse=True)
        return result

    def _analyse(self, name: str, data: bytes, sha256: str, depth: int, full: bool = True) -> list[Finding]:
        findings: list[Finding] = []
        ext = extension(name)
        kind = detect_type(data[:64])

        known = self.hash_db.lookup(sha256)
        if known:
            findings.append(Finding("hash", Severity.CRITICAL, f"Known malware: {known}", "malware"))

        # Disguises in the name
        disguised = double_extension(name)
        if disguised:
            findings.append(Finding("name", Severity.HIGH,
                                    f"Pretends to be a {disguised[0]} file but is really a {disguised[1]}"))
        if has_hidden_characters(name):
            findings.append(Finding("name", Severity.HIGH,
                                    "File name uses hidden characters to disguise its real type"))
        if kind in ("exe", "elf", "macho") and extension_mismatch(name, kind):
            findings.append(Finding("type", Severity.HIGH,
                                    f"This is a program disguised with a '{ext or 'missing'}' extension"))
        findings.extend(scan_name_for_hacktool(name, ext if ext in EXECUTABLE_EXTS or kind != "exe" else ".exe"))

        if not full:
            return findings

        # Zip files (including .docx/.xlsx) are compressed, so their raw bytes are
        # meaningless; the files inside are unpacked and checked individually instead.
        if kind != "zip":
            findings.extend(scan_eicar(data))
            is_script = ext in SCRIPT_EXTS or kind == "script"
            findings.extend(scan_patterns(data, is_script=is_script,
                                          is_program=kind in ("exe", "elf", "macho")))
            if self.yara and self.yara.available:
                findings.extend(self.yara.scan(data))

        if kind == "exe":
            findings.extend(pe.analyse(name, data))
        elif kind == "pdf" or ext == ".pdf":
            findings.extend(documents.analyse_pdf(data))
        elif kind == "rtf":
            findings.extend(documents.analyse_rtf(data))
        elif ext == ".lnk":
            findings.extend(documents.analyse_lnk(data))
        elif ext == ".torrent":
            torrent_findings, files = torrent.analyse(data)
            findings.extend(torrent_findings)
            if files:
                findings.append(Finding("torrent", Severity.INFO,
                                        f"Torrent lists {len(files)} file(s). A .torrent file cannot harm your "
                                        f"computer by itself - scan the downloaded files too.", INFO))

        if (kind == "ole" or ext in OFFICE_EXTS) and kind in ("ole", "zip"):
            findings.extend(documents.analyse_office(name, data, kind))
        elif kind == "zip" and self.options.scan_archives and ext not in OFFICE_EXTS:
            findings.extend(self._scan_zip(name, data, depth))
        elif kind in ("rar", "7z") or ext in ARCHIVE_EXTS - {".zip"}:
            findings.append(Finding("archive", Severity.INFO,
                                    "Can't look inside this kind of archive; extract it and scan the folder",
                                    INFO))
        return findings

    # ----------------------------------------------------------------- archives

    def _scan_zip(self, name: str, data: bytes, depth: int) -> list[Finding]:
        if depth >= MAX_ARCHIVE_DEPTH:
            return [Finding("archive", Severity.LOW, "Archive is nested very deeply; inner layers not checked")]
        findings: list[Finding] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, ValueError):
            return [Finding("archive", Severity.LOW, "Archive is damaged and could not be opened")]
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                findings.append(Finding("archive", Severity.MEDIUM,
                                        f"Archive holds {len(infos)} files; only the first "
                                        f"{MAX_ARCHIVE_MEMBERS} were checked"))
            declared = sum(i.file_size for i in infos)
            compressed = sum(i.compress_size for i in infos) or 1
            if declared > MAX_ARCHIVE_TOTAL and declared / compressed > 100:
                return findings + [Finding("archive", Severity.HIGH,
                                           "Zip bomb: a tiny archive that unpacks to a huge size to crash scanners")]
            encrypted_programs = []
            unpacked = 0
            for info in infos[:MAX_ARCHIVE_MEMBERS]:
                if info.is_dir():
                    continue
                inner_ext = extension(info.filename)
                if info.flag_bits & 0x1:
                    if inner_ext in EXECUTABLE_EXTS or inner_ext in SCRIPT_EXTS:
                        encrypted_programs.append(info.filename)
                    continue
                if info.file_size > MAX_CONTENT_BYTES or unpacked + info.file_size > MAX_ARCHIVE_TOTAL:
                    continue
                try:
                    inner = zf.read(info)
                except Exception:
                    findings.append(Finding("archive", Severity.LOW, f"Could not unpack '{info.filename}'"))
                    continue
                unpacked += len(inner)
                inner_sha = hashlib.sha256(inner).hexdigest()
                for f in self._analyse(info.filename, inner, inner_sha, depth + 1):
                    if f.severity == Severity.INFO and f.category == INFO and f.check == "signature":
                        continue
                    f.message = f"Inside '{info.filename}': {f.message}"
                    findings.append(f)
            if encrypted_programs:
                findings.append(Finding("archive", Severity.MEDIUM,
                                        "Password-protected archive hides programs from virus scanners: "
                                        + ", ".join(encrypted_programs[:5])))
        return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.check, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
