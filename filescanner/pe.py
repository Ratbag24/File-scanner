"""Checks for Windows programs (.exe / .dll)."""

from __future__ import annotations

import math
import time
from collections import Counter

from .models import INFO, Finding, Severity

try:
    import pefile
except ImportError:  # the scanner still works without it, just with fewer checks
    pefile = None

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", "pec1": "PECompact", "pec2": "PECompact", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".perplex": "Perplex", ".yp": "Y0da",
}

# Groups of Windows functions that together point to a specific behaviour.
_IMPORT_BEHAVIOURS = [
    ({"virtualallocex", "writeprocessmemory", "createremotethread"}, Severity.HIGH,
     "Can inject code into other running programs"),
    ({"ntunmapviewofsection", "setthreadcontext", "resumethread"}, Severity.HIGH,
     "Can hollow out another program and run inside it"),
    ({"setwindowshookexa", "getasynckeystate"}, Severity.MEDIUM,
     "Can record keyboard input (keylogger behaviour)"),
    ({"setwindowshookexw", "getasynckeystate"}, Severity.MEDIUM,
     "Can record keyboard input (keylogger behaviour)"),
    ({"urldownloadtofilea"}, Severity.MEDIUM, "Downloads files from the internet"),
    ({"urldownloadtofilew"}, Severity.MEDIUM, "Downloads files from the internet"),
    ({"cryptencrypt", "findfirstfilew", "movefileexw"}, Severity.MEDIUM,
     "Can encrypt and rename many files (possible ransomware)"),
    ({"adjusttokenprivileges", "openprocesstoken", "lookupprivilegevaluea"}, Severity.LOW,
     "Asks for extra system privileges"),
    ({"isdebuggerpresent", "checkremotedebuggerpresent"}, Severity.LOW,
     "Checks whether it is being analysed by a debugger"),
]


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = all the same, 8 = random-looking)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in Counter(data).values())


def analyse(path: str, data: bytes) -> list[Finding]:
    if pefile is None:
        return _analyse_without_pefile(data)
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        return [Finding("pe", Severity.MEDIUM, "Program file is malformed or deliberately corrupted")]
    try:
        return _analyse_pe(pe, data)
    finally:
        pe.close()


def _analyse_without_pefile(data: bytes) -> list[Finding]:
    findings = []
    if b"UPX!" in data[:4096] or b"UPX0" in data[:1024]:
        findings.append(Finding("pe", Severity.MEDIUM, "Program is compressed with the UPX packer"))
    if entropy(data[:4 << 20]) > 7.4:
        findings.append(Finding("pe", Severity.MEDIUM, "Most of the program is encrypted or compressed"))
    return findings


def _analyse_pe(pe, data: bytes) -> list[Finding]:
    findings: list[Finding] = []

    # Packers and scrambled code
    packers = set()
    high_entropy_code = []
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_section = None
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1", "replace").lower()
        if name in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name])
        is_code = bool(section.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        if is_code and section.SizeOfRawData > 1024 and section.get_entropy() > 7.2:
            high_entropy_code.append(name or "?")
        if section.contains_rva(entry):
            entry_section = section
        if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
            findings.append(Finding("pe", Severity.LOW,
                                    f"Section '{name}' is both writable and executable (self-modifying code)"))
    if packers:
        findings.append(Finding("pe", Severity.MEDIUM,
                                f"Program is packed with {', '.join(sorted(packers))} (hides what the code does)"))
    elif high_entropy_code:
        findings.append(Finding("pe", Severity.MEDIUM,
                                "Program code is encrypted or compressed (possible unknown packer)"))
    if entry_section is None and entry != 0:
        findings.append(Finding("pe", Severity.MEDIUM, "Program starts outside of any code section"))
    elif entry_section is not None and not entry_section.Characteristics & 0x20000000:
        findings.append(Finding("pe", Severity.MEDIUM, "Program starts in a section not marked as code"))

    # Imported Windows functions
    imports: set[str] = set()
    for entry_dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry_dll.imports:
            if imp.name:
                imports.add(imp.name.decode("latin-1", "replace").lower())
    for needed, severity, message in _IMPORT_BEHAVIOURS:
        if needed <= imports:
            findings.append(Finding("imports", severity, message))
    if imports and len(imports) < 6 and {"loadlibrarya", "getprocaddress"} & imports:
        findings.append(Finding("imports", Severity.MEDIUM,
                                "Hides which system functions it uses (loads them at run time)"))

    # Digital signature: we can only see whether one is present here; Windows
    # checks whether it is valid when you right-click > Properties > Digital Signatures.
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
    if security.VirtualAddress and security.Size:
        findings.append(Finding("signature", Severity.INFO,
                                "Has a digital signature (check the publisher in Windows file properties)", INFO))
    else:
        findings.append(Finding("signature", Severity.LOW, "Program is not digitally signed"))

    stamp = pe.FILE_HEADER.TimeDateStamp
    if stamp > time.time() + 86400 * 2:
        findings.append(Finding("pe", Severity.LOW, "Build date is in the future (faked)"))

    # Extra data glued onto the end of the program (common in droppers, but
    # also in normal installers, so it only counts as low).
    overlay = pe.get_overlay_data_start_offset()
    if overlay and len(data) - overlay > 1 << 20 and entropy(data[overlay:overlay + (1 << 20)]) > 7.5:
        findings.append(Finding("pe", Severity.LOW,
                                "Carries a large encrypted or compressed payload after the program"))
    return findings
