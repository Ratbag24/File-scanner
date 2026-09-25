"""Command-line interface: ``filescanner scan <files or folders>``."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

from . import __version__
from .models import Severity, Verdict
from .scanner import Scanner, ScanOptions
from .signatures import default_hash_db_path

# abuse.ch MalwareBazaar publishes free lists of recent malware fingerprints.
HASH_FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

_COLOURS = {Verdict.CLEAN: "\033[32m", Verdict.SUSPICIOUS: "\033[33m",
            Verdict.RISKY_TOOL: "\033[35m", Verdict.DANGEROUS: "\033[31m"}


def _colour(text: str, verdict: Verdict, enabled: bool) -> str:
    return f"{_COLOURS[verdict]}{text}\033[0m" if enabled else text


def cmd_scan(args) -> int:
    scanner = Scanner(ScanOptions(use_clamav=not args.no_clamav, clamav_path=args.clamav, use_yara=not args.no_yara,
                                  virustotal_key=args.vt_key, hash_db_path=args.hash_db))
    colour = sys.stdout.isatty() and not args.json
    results = []
    worst = Verdict.CLEAN
    for result in scanner.scan_paths(args.paths):
        results.append(result)
        worst = max(worst, result.verdict)
        if args.json:
            continue
        if result.verdict == Verdict.CLEAN and not args.verbose and not result.error:
            if not args.quiet:
                print(f"[{_colour('Clean', Verdict.CLEAN, colour)}] {result.path}")
            continue
        print(f"[{_colour(result.verdict.label, result.verdict, colour)}] {result.path}")
        if result.error:
            print(f"    ! could not scan: {result.error}")
        for f in result.findings:
            if f.severity == Severity.INFO and not args.verbose:
                continue
            print(f"    - ({f.severity.name.lower()}) {f.message}")

    if args.json:
        json.dump([r.to_dict() for r in results], sys.stdout, indent=2)
        print()
    else:
        counts = {v: sum(1 for r in results if r.verdict == v) for v in Verdict}
        print(f"\nScanned {len(results)} file(s): "
              + ", ".join(f"{counts[v]} {v.label.lower()}" for v in Verdict))
    # Exit code: 0 clean, 1 suspicious, 2 risky tool, 3 dangerous
    return int(worst)


def cmd_engines(args) -> int:
    for name, status in Scanner(ScanOptions()).engine_status().items():
        print(f"{name:28} {status}")
    return 0


def cmd_update(args) -> int:
    target = default_hash_db_path()
    print(f"Downloading recent malware fingerprints from {HASH_FEED_URL} ...")
    try:
        with urllib.request.urlopen(HASH_FEED_URL, timeout=60) as response:
            text = response.read().decode("utf-8", "replace")
    except OSError as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1
    hashes = [line.strip() for line in text.splitlines()
              if len(line.strip()) == 64 and not line.startswith("#")]
    if not hashes:
        print("The download did not contain any fingerprints; nothing was changed.", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# From MalwareBazaar (abuse.ch)\n"
                      + "\n".join(f"{h} MalwareBazaar sample" for h in hashes) + "\n", encoding="utf-8")
    print(f"Saved {len(hashes)} fingerprints to {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filescanner",
                                     description="Scan files, programs, documents and torrents for threats.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan files or folders")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--json", action="store_true", help="print results as JSON")
    scan.add_argument("-v", "--verbose", action="store_true", help="show informational notes too")
    scan.add_argument("-q", "--quiet", action="store_true", help="don't list clean files")
    scan.add_argument("--no-clamav", action="store_true", help="don't use ClamAV even if installed")
    scan.add_argument("--clamav", metavar="PATH", help="clamscan program or ClamAV folder, if not found automatically")
    scan.add_argument("--no-yara", action="store_true", help="don't use YARA rules")
    scan.add_argument("--vt-key", help="VirusTotal API key (or set VT_API_KEY)")
    scan.add_argument("--hash-db", help="extra text file of known-bad SHA-256 hashes")
    scan.set_defaults(func=cmd_scan)

    sub.add_parser("engines", help="show which scanners are available").set_defaults(func=cmd_engines)
    sub.add_parser("update", help="download the latest known-malware fingerprints").set_defaults(func=cmd_update)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
