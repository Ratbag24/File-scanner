"""Look inside .torrent files before anything is downloaded.

A .torrent file itself cannot harm your computer; it only lists the files you
would download. This module reads that list and warns about files that are
often used to spread malware, such as a "movie" that comes with an .exe.
"""

from __future__ import annotations

import os

from .filetypes import (ARCHIVE_EXTS, EXECUTABLE_EXTS, MEDIA_EXTS, double_extension,
                        has_hidden_characters)
from .models import HACKTOOL, HEURISTIC, Finding, Severity
from .signatures import scan_name_for_hacktool


class BencodeError(ValueError):
    pass


def bdecode(data: bytes):
    value, end = _decode(data, 0, 0)
    if end != len(data):
        raise BencodeError("trailing data after torrent")
    return value


def _decode(data: bytes, i: int, depth: int):
    if depth > 64:
        raise BencodeError("nested too deeply")
    if i >= len(data):
        raise BencodeError("unexpected end of data")
    c = data[i:i + 1]
    if c == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1:end]), end + 1
    if c == b"l":
        i += 1
        items = []
        while data[i:i + 1] != b"e":
            item, i = _decode(data, i, depth + 1)
            items.append(item)
        return items, i + 1
    if c == b"d":
        i += 1
        result = {}
        while data[i:i + 1] != b"e":
            key, i = _decode(data, i, depth + 1)
            if not isinstance(key, bytes):
                raise BencodeError("dictionary key is not a string")
            result[key], i = _decode(data, i, depth + 1)
        return result, i + 1
    if c.isdigit():
        colon = data.index(b":", i)
        length = int(data[i:colon])
        start = colon + 1
        if start + length > len(data):
            raise BencodeError("string runs past end of data")
        return data[start:start + length], start + length
    raise BencodeError(f"unexpected byte {c!r} at {i}")


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def list_files(meta: dict) -> tuple[str, list[tuple[str, int]]]:
    info = meta.get(b"info", {})
    name = _text(info.get(b"name.utf-8", info.get(b"name", b"")))
    files = []
    if b"files" in info:  # multi-file torrent
        for f in info[b"files"]:
            parts = f.get(b"path.utf-8", f.get(b"path", []))
            files.append((os.path.join(name, *(_text(p) for p in parts)), int(f.get(b"length", 0))))
    elif b"file tree" in info:  # BitTorrent v2
        def walk(tree, prefix):
            for key, sub in tree.items():
                if key == b"" and isinstance(sub, dict):
                    files.append((prefix, int(sub.get(b"length", 0))))
                elif isinstance(sub, dict):
                    walk(sub, os.path.join(prefix, _text(key)) if prefix else _text(key))
        walk(info[b"file tree"], name)
    else:
        files.append((name, int(info.get(b"length", 0))))
    return name, files


def analyse(data: bytes) -> tuple[list[Finding], list[tuple[str, int]]]:
    try:
        meta = bdecode(data)
        _, files = list_files(meta)
    except (BencodeError, ValueError, AttributeError, TypeError):
        return [Finding("torrent", Severity.LOW, "Torrent file is damaged and could not be read")], []

    findings: list[Finding] = []
    exts = [os.path.splitext(p)[1].lower() for p, _ in files]
    has_media = any(e in MEDIA_EXTS for e in exts)
    executables = [p for p, _ in files if os.path.splitext(p)[1].lower() in EXECUTABLE_EXTS]
    archives = [p for p, _ in files if os.path.splitext(p)[1].lower() in ARCHIVE_EXTS]

    for path, _size in files:
        disguised = double_extension(path)
        if disguised:
            findings.append(Finding("torrent", Severity.HIGH,
                                    f"'{os.path.basename(path)}' pretends to be a {disguised[0]} "
                                    f"but is really a {disguised[1]} program", HEURISTIC))
        if has_hidden_characters(path):
            findings.append(Finding("torrent", Severity.HIGH,
                                    f"'{path}' uses hidden characters to disguise its real type"))
        for f in scan_name_for_hacktool(path, os.path.splitext(path)[1].lower()):
            f.message = f"'{os.path.basename(path)}': {f.message.lower()}"
            findings.append(f)

    if has_media and executables:
        findings.append(Finding("torrent", Severity.HIGH,
                                "Video/music download also contains programs: "
                                + ", ".join(os.path.basename(p) for p in executables[:5])
                                + " (a very common way to spread malware)"))
    elif executables:
        findings.append(Finding("torrent", Severity.LOW,
                                f"Contains {len(executables)} program file(s); scan them after downloading"))
    if has_media and archives:
        findings.append(Finding("torrent", Severity.MEDIUM,
                                "Video/music download is packed in an archive (often hides malware; "
                                "real video releases rarely are)"))
    lowered = " ".join(p.lower() for p, _ in files)
    if any(k in lowered for k in ("password.txt", "codec", "player.exe", "install_codec")):
        findings.append(Finding("torrent", Severity.MEDIUM,
                                "Asks you to install a 'codec' or player, or includes a password file "
                                "(classic torrent malware tricks)"))
    if any(f.category == HACKTOOL for f in findings):
        findings.append(Finding("torrent", Severity.INFO,
                                "Cracked software is one of the most common sources of malware"))
    return findings, files
