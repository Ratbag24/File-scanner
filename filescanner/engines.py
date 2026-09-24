"""Optional outside scanners: ClamAV, YARA rules and VirusTotal.

Each one is used only if it is installed or configured, so the app still works
without them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .models import HACKTOOL, INFO, MALWARE, Finding, Severity

try:
    import yara
except ImportError:
    yara = None


def resource_dir() -> Path:
    """Folder holding bundled files, both when run from source and from the .exe."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "filescanner"


# --------------------------------------------------------------------- ClamAV

def find_clamscan() -> str | None:
    for name in ("clamdscan", "clamscan"):
        found = shutil.which(name)
        if found:
            return found
    for guess in (r"C:\Program Files\ClamAV\clamscan.exe", r"C:\Program Files (x86)\ClamAV\clamscan.exe"):
        if os.path.isfile(guess):
            return guess
    return None


class ClamAV:
    def __init__(self, binary: str | None = None):
        self.binary = binary or find_clamscan()

    @property
    def available(self) -> bool:
        return self.binary is not None

    def scan(self, path: str) -> list[Finding]:
        if not self.binary:
            return []
        try:
            proc = subprocess.run([self.binary, "--no-summary", "--infected", path],
                                  capture_output=True, text=True, timeout=600,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [Finding("clamav", Severity.INFO, f"ClamAV could not scan this file: {exc}", INFO)]
        findings = []
        for line in proc.stdout.splitlines():
            if line.endswith(" FOUND"):
                name = line.rsplit(":", 1)[-1].replace(" FOUND", "").strip()
                # ClamAV names cracks and hacking tools "PUA" (potentially unwanted).
                if name.startswith("PUA."):
                    findings.append(Finding("clamav", Severity.MEDIUM,
                                            f"ClamAV: potentially unwanted program ({name})", HACKTOOL))
                else:
                    findings.append(Finding("clamav", Severity.CRITICAL, f"ClamAV detected {name}", MALWARE))
        return findings


# ----------------------------------------------------------------------- YARA

class YaraRules:
    """Loads every .yar / .yara file from the bundled rules folder and any extra folder."""

    def __init__(self, extra_dir: str | None = None):
        self.rules = None
        self.error: str | None = None
        if yara is None:
            return
        files = {}
        for folder in (resource_dir() / "rules", extra_dir or os.environ.get("FILESCANNER_RULES")):
            if folder and os.path.isdir(folder):
                for entry in sorted(os.listdir(folder)):
                    if entry.lower().endswith((".yar", ".yara")):
                        files[f"{len(files)}_{entry}"] = os.path.join(folder, entry)
        if not files:
            return
        try:
            self.rules = yara.compile(filepaths=files)
        except yara.Error as exc:
            self.error = str(exc)

    @property
    def available(self) -> bool:
        return self.rules is not None

    def scan(self, data: bytes) -> list[Finding]:
        if self.rules is None:
            return []
        try:
            matches = self.rules.match(data=data, timeout=60)
        except yara.Error as exc:
            return [Finding("yara", Severity.INFO, f"YARA could not scan this file: {exc}", INFO)]
        findings = []
        for match in matches:
            meta = match.meta
            severity = Severity.__members__.get(str(meta.get("severity", "medium")).upper(), Severity.MEDIUM)
            category = str(meta.get("category", "heuristic"))
            message = str(meta.get("description", match.rule))
            findings.append(Finding("yara", severity, f"{message} [{match.rule}]", category))
        return findings


# ----------------------------------------------------------------- VirusTotal

VT_KEY_ENV = "VT_API_KEY"


def virustotal_lookup(sha256: str, api_key: str | None = None, timeout: float = 15) -> list[Finding]:
    """Look the file's fingerprint up on VirusTotal. The file itself is never uploaded."""
    api_key = api_key or os.environ.get(VT_KEY_ENV)
    if not api_key:
        return []
    request = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                     headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            report = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return [Finding("virustotal", Severity.INFO, "VirusTotal has never seen this file", INFO)]
        return [Finding("virustotal", Severity.INFO, f"VirusTotal lookup failed (HTTP {exc.code})", INFO)]
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return [Finding("virustotal", Severity.INFO, f"VirusTotal lookup failed: {exc}", INFO)]

    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    summary = f"VirusTotal: {malicious}/{total} engines flag this file" + (f" ({label})" if label else "")
    if malicious >= 5:
        return [Finding("virustotal", Severity.CRITICAL, summary, MALWARE)]
    if malicious >= 1 or suspicious >= 3:
        return [Finding("virustotal", Severity.HIGH, summary, MALWARE)]
    return [Finding("virustotal", Severity.INFO, summary, INFO)]
