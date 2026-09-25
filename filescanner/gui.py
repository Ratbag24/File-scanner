"""Desktop window for the scanner (built with tkinter, which ships with Python)."""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .models import ScanResult, Severity, Verdict
from .scanner import Scanner, ScanOptions
from .signatures import default_hash_db_path

try:  # optional: lets you drag files from Explorer / Finder onto the window
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # optional library missing or broken: run without it
    TkinterDnD = None

VERDICT_COLOURS = {
    Verdict.CLEAN: "#1b7f3b",
    Verdict.SUSPICIOUS: "#b36b00",
    Verdict.RISKY_TOOL: "#8a3fb3",
    Verdict.DANGEROUS: "#c62828",
}


def app_dir() -> Path:
    return default_hash_db_path().parent


def load_settings() -> dict:
    try:
        return json.loads((app_dir() / "settings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(settings: dict) -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    (app_dir() / "settings.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")


class ScannerApp:
    def __init__(self, root: tk.Tk, drag_and_drop: bool = False):
        self.root = root
        self.drag_and_drop = drag_and_drop
        self.settings = load_settings()
        self.targets: list[str] = []
        self.results: dict[str, ScanResult] = {}
        self.events: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None

        root.title(f"File Scanner {__version__}")
        root.geometry("980x640")
        root.minsize(720, 480)
        self._build()
        self._refresh_targets()
        root.after(100, self._poll)

    # ------------------------------------------------------------------ layout

    def _build(self):
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")

        top = ttk.Frame(self.root, padding=(12, 12, 12, 6))
        top.pack(fill="x")
        ttk.Button(top, text="Add files…", command=self.add_files).pack(side="left")
        ttk.Button(top, text="Add folder…", command=self.add_folder).pack(side="left", padx=6)
        ttk.Button(top, text="Clear", command=self.clear).pack(side="left")
        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(18, 6))
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left")
        ttk.Button(top, text="Settings", command=self.open_settings).pack(side="right")
        ttk.Button(top, text="Save report…", command=self.save_report).pack(side="right", padx=6)

        self.target_label = ttk.Label(self.root, padding=(12, 0), foreground="#555")
        self.target_label.pack(fill="x")

        body = ttk.PanedWindow(self.root, orient="vertical")
        body.pack(fill="both", expand=True, padx=12, pady=6)

        table_frame = ttk.Frame(body)
        columns = ("name", "verdict", "reason")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        for col, title, width in (("name", "File", 260), ("verdict", "Result", 100),
                                  ("reason", "Main reason", 520)):
            self.table.heading(col, text=title)
            self.table.column(col, width=width, anchor="w", stretch=col != "verdict")
        for verdict, colour in VERDICT_COLOURS.items():
            self.table.tag_configure(verdict.name, foreground=colour)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self._show_details)
        body.add(table_frame, weight=3)

        detail_frame = ttk.Frame(body)
        self.details = tk.Text(detail_frame, height=10, wrap="word", relief="flat",
                               font=("Segoe UI", 10) if os.name == "nt" else None)
        self.details.configure(state="disabled")
        actions = ttk.Frame(detail_frame)
        self.quarantine_btn = ttk.Button(actions, text="Quarantine file", state="disabled",
                                         command=self.quarantine_selected)
        self.quarantine_btn.pack(side="left")
        self.reveal_btn = ttk.Button(actions, text="Show in folder", state="disabled",
                                     command=self.reveal_selected)
        self.reveal_btn.pack(side="left", padx=6)
        actions.pack(fill="x", pady=(0, 4))
        self.details.pack(fill="both", expand=True)
        body.add(detail_frame, weight=2)

        bottom = ttk.Frame(self.root, padding=(12, 0, 12, 10))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=160)
        self.progress.pack(side="right")
        self.status = ttk.Label(bottom, text="Add files or folders, then press Scan.")
        self.status.pack(side="left", fill="x", expand=True)

        if self.drag_and_drop:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self._on_drop)

    # ----------------------------------------------------------------- targets

    def add_files(self):
        self._add(filedialog.askopenfilenames(title="Choose files to scan"))

    def add_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder to scan")
        if folder:
            self._add([folder])

    def _on_drop(self, event):
        self._add(self.root.tk.splitlist(event.data))

    def _add(self, paths):
        for path in paths:
            if path and path not in self.targets:
                self.targets.append(path)
        self._refresh_targets()

    def clear(self):
        if self.worker and self.worker.is_alive():
            return
        self.targets.clear()
        self.results.clear()
        self.table.delete(*self.table.get_children())
        self._set_details("")
        self._refresh_targets()

    def _refresh_targets(self):
        if not self.targets:
            hint = " (or drag them onto this window)" if self.drag_and_drop else ""
            self.target_label.configure(text=f"Nothing selected yet{hint}.")
        else:
            shown = ", ".join(os.path.basename(p.rstrip("/\\")) or p for p in self.targets[:4])
            more = f" and {len(self.targets) - 4} more" if len(self.targets) > 4 else ""
            self.target_label.configure(text=f"To scan: {shown}{more}")

    # -------------------------------------------------------------------- scan

    def start_scan(self):
        if not self.targets:
            messagebox.showinfo("File Scanner", "Add some files or a folder to scan first.")
            return
        self.results.clear()
        self.table.delete(*self.table.get_children())
        self.cancel.clear()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.start(12)
        options = ScanOptions(virustotal_key=self.settings.get("virustotal_key") or None,
                              use_clamav=self.settings.get("use_clamav", True),
                              clamav_path=self.settings.get("clamav_path") or None)
        self.worker = threading.Thread(target=self._run_scan, args=(list(self.targets), options),
                                       daemon=True)
        self.worker.start()

    def _run_scan(self, targets, options):
        started = time.time()
        try:
            scanner = Scanner(options)
            for result in scanner.scan_paths(targets, progress=lambda p: self.events.put(("progress", p)),
                                             cancel=self.cancel):
                self.events.put(("result", result))
        except Exception as exc:  # keep the window alive whatever happens
            self.events.put(("error", str(exc)))
        self.events.put(("done", time.time() - started))

    def stop_scan(self):
        self.cancel.set()
        self.status.configure(text="Stopping…")

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    self.status.configure(text=f"Scanning {payload}")
                elif kind == "result":
                    self._add_result(payload)
                elif kind == "status":
                    self.status.configure(text=payload)
                elif kind == "error":
                    messagebox.showerror("File Scanner", f"The scan stopped because of an error:\n{payload}")
                elif kind == "done":
                    self._finish(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _add_result(self, result: ScanResult):
        self.results[result.path] = result
        verdict = result.verdict
        reasons = [f.message for f in result.findings if f.severity > Severity.LOW]
        reason = result.error or (reasons[0] if reasons else "No threats found")
        self.table.insert("", "end", iid=result.path, values=(os.path.basename(result.path), verdict.label, reason),
                          tags=(verdict.name,))
        # Keep the worst files at the top.
        rows = sorted(self.table.get_children(), key=lambda iid: -self.results[iid].verdict)
        for index, iid in enumerate(rows):
            self.table.move(iid, "", index)

    def _finish(self, seconds: float):
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        counts = {v: sum(1 for r in self.results.values() if r.verdict == v) for v in Verdict}
        stopped = " (stopped early)" if self.cancel.is_set() else ""
        self.status.configure(
            text=f"Scanned {len(self.results)} file(s) in {seconds:.1f}s{stopped}: "
                 f"{counts[Verdict.DANGEROUS]} dangerous, {counts[Verdict.RISKY_TOOL]} risky tools, "
                 f"{counts[Verdict.SUSPICIOUS]} suspicious, {counts[Verdict.CLEAN]} clean.")
        if counts[Verdict.DANGEROUS]:
            messagebox.showwarning("File Scanner",
                                   f"{counts[Verdict.DANGEROUS]} dangerous file(s) found. Don't open them. "
                                   "Select one and press 'Quarantine file' to move it somewhere safe.")

    # ----------------------------------------------------------------- details

    def _selected(self) -> ScanResult | None:
        selection = self.table.selection()
        return self.results.get(selection[0]) if selection else None

    def _show_details(self, _event=None):
        result = self._selected()
        if result is None:
            return
        lines = [f"{result.verdict.label.upper()}  -  {result.path}",
                 f"Size: {result.size:,} bytes    SHA-256: {result.sha256}", ""]
        explanation = {
            Verdict.DANGEROUS: "Matches a known virus or malware. Do not open it.",
            Verdict.RISKY_TOOL: "Looks like a crack, keygen, cheat or hacking tool. These are not always "
                                "viruses, but they are very often bundled with them.",
            Verdict.SUSPICIOUS: "Has several warning signs. It may be safe, but only open it if you trust "
                                "where it came from. A VirusTotal key in Settings gives a second opinion.",
            Verdict.CLEAN: "No threats found. No scanner is perfect, so still only run programs you trust.",
        }[result.verdict]
        lines += [explanation, ""]
        if result.error:
            lines.append(f"Could not scan: {result.error}")
        for f in result.findings:
            lines.append(f"  [{f.severity.name.lower():8}] {f.message}")
        self._set_details("\n".join(lines))
        state = "normal" if os.path.exists(result.path) else "disabled"
        self.quarantine_btn.configure(state=state if result.verdict != Verdict.CLEAN else "disabled")
        self.reveal_btn.configure(state=state)

    def _set_details(self, text: str):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def quarantine_selected(self):
        result = self._selected()
        if result is None:
            return
        target_dir = app_dir() / "quarantine"
        if not messagebox.askyesno(
                "Quarantine",
                f"Move this file into quarantine?\n\n{result.path}\n\nIt will be renamed so it can't run, and "
                f"kept in:\n{target_dir}\n\nYou can move it back later if it turns out to be safe."):
            return
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            destination = target_dir / f"{result.sha256[:12]}_{os.path.basename(result.path)}.quarantined"
            shutil.move(result.path, destination)
        except OSError as exc:
            messagebox.showerror("Quarantine", f"Could not move the file:\n{exc}")
            return
        self.table.set(result.path, "reason", f"Moved to quarantine: {destination}")
        self.quarantine_btn.configure(state="disabled")
        self.reveal_btn.configure(state="disabled")

    def reveal_selected(self):
        result = self._selected()
        if result is None:
            return
        folder = os.path.dirname(result.path)
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.Popen([opener, folder])
        except OSError:
            pass

    # ----------------------------------------------------------------- report

    def save_report(self):
        if not self.results:
            messagebox.showinfo("File Scanner", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(title="Save report", defaultextension=".txt",
                                            filetypes=[("Text report", "*.txt"), ("JSON", "*.json")])
        if not path:
            return
        ordered = sorted(self.results.values(), key=lambda r: -r.verdict)
        if path.lower().endswith(".json"):
            text = json.dumps([r.to_dict() for r in ordered], indent=2)
        else:
            lines = [f"File Scanner {__version__} report - {time.strftime('%Y-%m-%d %H:%M')}", ""]
            for r in ordered:
                lines.append(f"[{r.verdict.label}] {r.path}")
                lines += [f"    ({f.severity.name.lower()}) {f.message}" for f in r.findings]
            text = "\n".join(lines) + "\n"
        Path(path).write_text(text, encoding="utf-8")
        self.status.configure(text=f"Report saved to {path}")

    # --------------------------------------------------------------- settings

    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.transient(self.root)
        win.resizable(False, False)
        frame = ttk.Frame(win, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="VirusTotal API key (optional)").grid(row=0, column=0, sticky="w")
        key_var = tk.StringVar(value=self.settings.get("virustotal_key", ""))
        ttk.Entry(frame, textvariable=key_var, width=70, show="•").grid(row=1, column=0, sticky="we")
        ttk.Label(frame, foreground="#555", wraplength=480, justify="left",
                  text="Get a free key at virustotal.com (sign up > API key). Only each file's "
                       "fingerprint is sent, never the file itself. Free keys allow 4 lookups a minute."
                  ).grid(row=2, column=0, sticky="w", pady=(2, 12))

        clam_var = tk.BooleanVar(value=self.settings.get("use_clamav", True))
        ttk.Checkbutton(frame, text="Use ClamAV if it is installed", variable=clam_var).grid(
            row=3, column=0, sticky="w")
        clam_path = tk.StringVar(value=self.settings.get("clamav_path", ""))
        clam_row = ttk.Frame(frame)
        clam_row.grid(row=4, column=0, sticky="we", pady=(4, 0))
        ttk.Label(clam_row, text="ClamAV location:").pack(side="left")
        ttk.Entry(clam_row, textvariable=clam_path, width=46).pack(side="left", padx=6, fill="x", expand=True)

        status_label = ttk.Label(frame, justify="left")
        status_label.grid(row=5, column=0, sticky="w", pady=12)

        def refresh_status():
            status = Scanner(ScanOptions(virustotal_key=key_var.get() or None, use_clamav=clam_var.get(),
                                         clamav_path=clam_path.get().strip() or None)).engine_status()
            status_label.configure(text="Scanners\n" + "\n".join(f"{n}: {v}" for n, v in status.items()))

        def choose_clamav():
            chosen = filedialog.askopenfilename(
                parent=win, title="Find clamscan.exe (usually in C:\\Program Files\\ClamAV)",
                filetypes=[("clamscan", "clamscan*"), ("All files", "*")])
            if chosen:
                clam_path.set(chosen)
                refresh_status()

        ttk.Button(clam_row, text="Browse…", command=choose_clamav).pack(side="left")
        ttk.Label(frame, foreground="#555", wraplength=480, justify="left",
                  text="Leave empty to find ClamAV automatically. If it says 'not found', press Browse "
                       "and pick clamscan.exe from the folder ClamAV was installed to."
                  ).grid(row=6, column=0, sticky="w")
        refresh_status()

        def update_hashes():
            from .cli import cmd_update

            def run():
                ok = cmd_update(None) == 0
                self.events.put(("status", "Malware fingerprints updated." if ok else
                                 "Couldn't download fingerprints (check your internet connection)."))

            self.status.configure(text="Downloading latest malware fingerprints…")
            threading.Thread(target=run, daemon=True).start()

        def save():
            self.settings["virustotal_key"] = key_var.get().strip()
            self.settings["use_clamav"] = clam_var.get()
            self.settings["clamav_path"] = clam_path.get().strip()
            try:
                save_settings(self.settings)
            except OSError as exc:
                messagebox.showerror("Settings", f"Couldn't save settings:\n{exc}")
            win.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, sticky="we", pady=(12, 0))
        ttk.Button(buttons, text="Update malware fingerprints", command=update_hashes).pack(side="left")
        ttk.Button(buttons, text="Save", command=save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right", padx=6)


def main(paths: list[str] | None = None) -> int:
    root = None
    if TkinterDnD is not None:
        try:
            root = TkinterDnD.Tk()
        except Exception:  # drag-and-drop library present but unusable
            pass
    if root is None:
        root = tk.Tk()
    app = ScannerApp(root, drag_and_drop=isinstance(root, TkinterDnD.Tk) if TkinterDnD else False)
    if paths:
        app._add(paths)
    root.mainloop()
    return 0
