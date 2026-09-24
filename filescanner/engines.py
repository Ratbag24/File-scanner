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
except Exception:  # optional library missing or broken: run without it
    yara = None


def resource_dir() -> Path:
    """Folder holding bundled files, both when run from source and from the .exe."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "filescanner"


# --------------------------------------------------------------------- ClamAV

CLAMSCAN_EXE = "clamscan.exe" if os.name == "nt" else "clamscan"


def _clamscan_in(folder: str | os.PathLike | None) -> str | None:
    """Find clamscan in a folder or one level below it (e.g. an extracted zip)."""
    if not folder:
        return None
    folder = Path(folder)
    if folder.is_file():
        return str(folder) if folder.name.lower().startswith("clamscan") else None
    if not folder.is_dir():
        return None
    direct = folder / CLAMSCAN_EXE
    if direct.is_file():
        return str(direct)
    try:
        for child in sorted(folder.iterdir()):
            if child.is_dir() and (child / CLAMSCAN_EXE).is_file():
                return str(child / CLAMSCAN_EXE)
    except OSError:
        pass
    return None


def _registry_install_dirs() -> list[str]:
    """Install folders of anything named ClamAV in Windows' list of installed programs."""
    try:
        import winreg
    except ImportError:
        return []
    found = []
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                root = winreg.OpenKey(hive, uninstall, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with root:
                for i in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, i)) as key:
                            name = str(winreg.QueryValueEx(key, "DisplayName")[0])
                            if "clamav" in name.lower():
                                found.append(str(winreg.QueryValueEx(key, "InstallLocation")[0]))
                    except OSError:
                        continue
    return found


def find_clamscan(configured: str | None = None) -> str | None:
    """Locate clamscan.

    Only clamscan is used: clamdscan needs the separate clamd service running and
    otherwise fails without reporting anything.
    """
    candidates = [configured, shutil.which("clamscan")]
    for var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA", "USERPROFILE"):
        base = os.environ.get(var)
        if base:
            candidates += [os.path.join(base, "ClamAV"), os.path.join(base, "Programs", "ClamAV")]
    candidates += [r"C:\Program Files\ClamAV", r"C:\Program Files (x86)\ClamAV", r"C:\ClamAV"]
    candidates += _registry_install_dirs()
    for candidate in candidates:
        found = _clamscan_in(candidate)
        if found:
            return found
    return None


class ClamAV:
    def __init__(self, configured: str | None = None):
        self.binary = find_clamscan(configured)

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
        # Exit code 2 means ClamAV itself failed (most often: no virus list yet).
        if proc.returncode == 2 and " FOUND" not in proc.stdout:
            problem = (proc.stderr.strip().splitlines() or ["unknown error"])[-1]
            if "database" in proc.stderr.lower() or "cvd" in proc.stderr.lower():
                problem = "it has no virus list yet. Run freshclam.exe to download one"
            return [Finding("clamav", Severity.LOW, f"ClamAV couldn't check this file: {problem}", INFO)]
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
