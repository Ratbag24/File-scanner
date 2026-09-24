"""Checks for Office documents, PDFs, RTF files and Windows shortcuts."""

from __future__ import annotations

import io
import re
import zipfile

from .models import HEURISTIC, Finding, Severity

try:
    from oletools.olevba import VBA_Parser
except Exception:  # optional library missing or broken: run without it
    VBA_Parser = None

# Keywords in macro code that point to harmful behaviour.
_MACRO_KEYWORDS = [
    (r"(?i)\b(auto_?open|document_open|workbook_open|autoexec|document_close)\b",
     Severity.MEDIUM, "Macro runs automatically when the document is opened"),
    (r"(?i)\b(shell|wscript\.shell|shellexecute|createobject\(\"shell)",
     Severity.HIGH, "Macro can run programs on your computer"),
    (r"(?i)(urldownloadtofile|msxml2\.xmlhttp|winhttp|\.responsebody|adodb\.stream)",
     Severity.HIGH, "Macro downloads files from the internet"),
    (r"(?i)\bpowershell\b", Severity.HIGH, "Macro starts PowerShell"),
    (r"(?i)\b(chrw?\(\d+\)\s*&\s*){6,}", Severity.MEDIUM, "Macro code is obfuscated"),
    (r"(?i)\b(kill|filecopy|savetofile)\b", Severity.LOW, "Macro writes or deletes files"),
]


def _macro_findings(code: str) -> list[Finding]:
    findings = [Finding("macro", Severity.MEDIUM, "Document contains macros (code that can run)")]
    for pattern, severity, message in _MACRO_KEYWORDS:
        if re.search(pattern, code):
            findings.append(Finding("macro", severity, message))
    return findings


def _extract_macro_code(name: str, data: bytes) -> str | None:
    """Return macro source code, "" when macros exist but can't be read, or None."""
    if VBA_Parser is not None:
        try:
            parser = VBA_Parser(name, data=data)
            try:
                if not parser.detect_vba_macros():
                    return None
                return "\n".join(code for *_rest, code in parser.extract_macros() if code)
            finally:
                parser.close()
        except Exception:
            pass
    # Fallback: look for the macro storage by name.
    if b"vbaProject.bin" in data or b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data:
        return data.decode("latin-1")
    return None


def analyse_office(name: str, data: bytes, kind: str) -> list[Finding]:
    findings: list[Finding] = []
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                rels = [n for n in names if n.endswith(".rels")]
                for rel in rels:
                    text = zf.read(rel).decode("utf-8", "replace")
                    # Remote templates are a common way to pull in macros later.
                    if re.search(r'(?i)TargetMode="External"', text) and re.search(
                            r"(?i)(attachedTemplate|oleObject|frame)", text):
                        findings.append(Finding("document", Severity.HIGH,
                                                "Loads a template or object from the internet when opened"))
                        break
                if any(n.lower().endswith(".bin") and "embeddings" in n.lower() for n in names):
                    findings.append(Finding("document", Severity.LOW, "Contains embedded objects"))
        except zipfile.BadZipFile:
            return [Finding("document", Severity.MEDIUM, "Document is damaged or deliberately malformed")]

    code = _extract_macro_code(name, data)
    if code is not None:
        findings.extend(_macro_findings(code))
    if kind == "ole" and re.search(rb"(?i)Equation\.3|Equation Native", data):
        findings.append(Finding("document", Severity.HIGH,
                                "Contains an Equation Editor object (used by a well-known Office exploit)"))
    return findings


_PDF_KEYS = [
    (rb"/JavaScript|/JS\s*[(<]", Severity.MEDIUM, "PDF contains JavaScript"),
    (rb"/Launch", Severity.HIGH, "PDF can launch programs"),
    (rb"/OpenAction|/AA\s*<<", Severity.LOW, "PDF runs an action automatically when opened"),
    (rb"/EmbeddedFile", Severity.LOW, "PDF has files attached inside it"),
    (rb"/SubmitForm", Severity.LOW, "PDF can send data to a website"),
    (rb"/RichMedia|/XFA", Severity.LOW, "PDF contains rich media or XFA forms"),
]


def analyse_pdf(data: bytes) -> list[Finding]:
    findings = []
    for pattern, severity, message in _PDF_KEYS:
        if re.search(pattern, data):
            findings.append(Finding("pdf", severity, message))
    # JavaScript + automatic action together is the classic malicious-PDF pattern.
    has_js = any(f.message.startswith("PDF contains JavaScript") for f in findings)
    has_auto = any("automatically" in f.message for f in findings)
    if has_js and has_auto:
        findings.append(Finding("pdf", Severity.HIGH, "PDF runs JavaScript as soon as it is opened"))
    if re.search(rb"(?i)\.exe\b", data) and any(f.message.startswith("PDF has files") for f in findings):
        findings.append(Finding("pdf", Severity.HIGH, "PDF has a program attached inside it"))
    return findings


def analyse_rtf(data: bytes) -> list[Finding]:
    findings = []
    if re.search(rb"\\objdata|\\objupdate|\\object", data):
        findings.append(Finding("document", Severity.MEDIUM, "RTF document contains embedded objects"))
    if re.search(rb"(?i)equation\.3|0002ce02", data):
        findings.append(Finding("document", Severity.HIGH,
                                "RTF contains an Equation Editor object (used by a well-known Office exploit)"))
    return findings


def analyse_lnk(data: bytes) -> list[Finding]:
    text = data.decode("utf-16-le", "ignore") + data.decode("latin-1")
    if re.search(r"(?i)(powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil)", text):
        return [Finding("shortcut", Severity.HIGH,
                        "Shortcut runs a system tool (a common trick in email attachments)", HEURISTIC)]
    return []
