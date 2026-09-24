"""Work out what a file really is from its first bytes, not its name."""

from __future__ import annotations

import os

# (magic bytes, offset, type name)
_MAGIC = [
    (b"MZ", 0, "exe"),
    (b"\x7fELF", 0, "elf"),
    (b"\xcf\xfa\xed\xfe", 0, "macho"),
    (b"\xce\xfa\xed\xfe", 0, "macho"),
    (b"\xca\xfe\xba\xbe", 0, "macho"),
    (b"%PDF", 0, "pdf"),
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"{\\rtf", 0, "rtf"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF8", 0, "gif"),
    (b"ID3", 0, "mp3"),
    (b"\x1aE\xdf\xa3", 0, "mkv"),
    (b"RIFF", 0, "riff"),
    (b"ftyp", 4, "mp4"),
    (b"OggS", 0, "ogg"),
    (b"fLaC", 0, "flac"),
    (b"#!", 0, "script"),
]

EXECUTABLE_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".sys",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".lnk", ".jar", ".reg", ".app", ".dmg", ".pkg", ".sh",
    ".apk", ".appx", ".msix", ".iso", ".img", ".vhd", ".vhdx", ".chm", ".scf",
}

MEDIA_EXTS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg",
    ".mpeg", ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".srt", ".sub",
}

DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt",
    ".pptx", ".pptm", ".rtf", ".txt", ".odt", ".ods", ".epub",
}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".tar", ".tgz", ".bz2", ".xz"}

# Which extensions each detected type is allowed to use.
_EXPECTED_EXTS = {
    "exe": {".exe", ".dll", ".scr", ".sys", ".cpl", ".com", ".ocx", ".drv", ".efi", ".mui", ".pyd"},
    "elf": {"", ".so", ".bin", ".run", ".elf", ".out"},
    "macho": {"", ".dylib", ".bundle", ".so"},
    "pdf": {".pdf"},
    "zip": {".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".jar",
            ".apk", ".odt", ".ods", ".odp", ".epub", ".xpi", ".crx", ".appx",
            ".msix", ".nupkg", ".whl", ".cbz", ".vsix", ".ipa", ".3mf"},
    "ole": {".doc", ".xls", ".ppt", ".msi", ".msp", ".msg", ".dot", ".xlt", ".pot", ".pub", ".vsd"},
    "rar": {".rar", ".cbr"},
    "7z": {".7z"},
    "gzip": {".gz", ".tgz"},
    "rtf": {".rtf", ".doc"},
}


def detect_type(header: bytes) -> str | None:
    for magic, offset, name in _MAGIC:
        if header[offset:offset + len(magic)] == magic:
            return name
    return None


def extension(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def extension_mismatch(path: str, detected: str | None) -> bool:
    """True when a risky file type is disguised under the wrong extension."""
    expected = _EXPECTED_EXTS.get(detected or "")
    if expected is None:
        return False
    return extension(path) not in expected


def double_extension(name: str) -> tuple[str, str] | None:
    """Detect names like ``holiday.jpg.exe`` or ``movie.mp4   .scr``.

    Returns (fake extension, real extension) when the name is disguised.
    """
    base = os.path.basename(name).lower()
    parts = base.split(".")
    if len(parts) < 3:
        return None
    real = "." + parts[-1].strip()
    fake = "." + parts[-2].strip()
    if real in EXECUTABLE_EXTS and fake in (MEDIA_EXTS | DOCUMENT_EXTS | IMAGE_EXTS):
        return fake, real
    return None


def has_hidden_characters(name: str) -> bool:
    """Right-to-left override and similar tricks that make ``exe`` look like ``gpj``."""
    return any(ch in name for ch in ("‮", "‭", "‎", "‏", "⁦", "⁧", "⁨"))
