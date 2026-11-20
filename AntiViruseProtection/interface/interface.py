import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from engine import engine as scan_engine
    ENGINE_IMPORT_ERROR = None
except ImportError as exc:
    scan_engine = None
    ENGINE_IMPORT_ERROR = exc


COLORS = {
    "bg": "#0B090B",
    "top": "#10090C",
    "sidebar": "#100C0F",
    "panel": "#171115",
    "panel_alt": "#1D1318",
    "border": "#38202A",
    "accent": "#BB1330",
    "accent_hover": "#D51A3C",
    "accent_soft": "#35101B",
    "text": "#F5EFF1",
    "muted": "#AA9BA1",
    "muted2": "#756970",
    "green": "#28D17C",
    "yellow": "#E5B454",
}

FONT = "Segoe UI"


class StasivynSecurity:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Stasivyn Security")
        self.root.geometry("1240x800")
        self.root.minsize(1050, 700)
        self.root.configure(bg=COLORS["bg"])

        self.current_page = "Dashboard"
        self.last_scan = "Never"
        self.last_scan_summary = None
        self.scan_running = False
        self.scan_thread = None
        self.scan_cancel_event = None
        self.scan_queue = queue.Queue()

        self.scan_status_var = tk.StringVar(
            root, value="Idle — no scan has been started."
        )
        self.scan_detail_var = tk.StringVar(root, value="Files scanned: 0")
        self.engine_status_var = tk.StringVar(root, value=self._engine_status_text())
        self.cancel_scan_button = None

        self._build_shell()
        self.show_page("Dashboard")

    def _build_shell(self):
        topbar = tk.Frame(
            self.root,
            bg=COLORS["top"],
            height=58,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        topbar.pack(side="top", fill="x")
        topbar.pack_propagate(False)

        tk.Label(
            topbar,
            text="Stasivyn Security",
            bg=COLORS["top"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(side="left", padx=24)

        body = tk.Frame(self.root, bg=COLORS["bg"])
        body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(
            body,
            bg=COLORS["sidebar"],
            width=228,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(
            self.sidebar,
            text="WORKSPACE",
            bg=COLORS["sidebar"],
            fg=COLORS["muted2"],
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=22, pady=(28, 12))

        self.nav_buttons = {}
        for name, symbol in [
            ("Dashboard", "▦"),
            ("Scan Center", "⌕"),
            ("Quarantine", "⬡"),
        ]:
            self._add_nav(name, symbol)

        tk.Frame(self.sidebar, bg=COLORS["border"], height=1).pack(
            fill="x", padx=18, pady=(20, 18)
        )
        tk.Label(
            self.sidebar,
            text="PREFERENCES",
            bg=COLORS["sidebar"],
            fg=COLORS["muted2"],
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=22, pady=(0, 12))
        self._add_nav("Settings", "⚙")
        self._add_nav("About", "ⓘ")

        footer = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        footer.pack(side="bottom", fill="x", padx=20, pady=22)
        tk.Frame(footer, bg=COLORS["border"], height=1).pack(fill="x", pady=(0, 14))
        tk.Label(
            footer,
            text="ENGINE STATUS",
            bg=COLORS["sidebar"],
            fg=COLORS["muted2"],
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            footer,
            textvariable=self.engine_status_var,
            bg=COLORS["sidebar"],
            fg=COLORS["green"] if scan_engine is not None else COLORS["yellow"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(8, 0))

        self.content = tk.Frame(body, bg=COLORS["bg"])
        self.content.pack(side="left", fill="both", expand=True)

    def _add_nav(self, name, symbol):
        button = tk.Button(
            self.sidebar,
            text=f"{symbol}    {name}",
            anchor="w",
            command=lambda page=name: self.show_page(page),
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            activebackground=COLORS["accent_soft"],
            activeforeground=COLORS["text"],
            relief="flat",
            bd=0,
            font=(FONT, 10),
            padx=18,
            pady=12,
            cursor="hand2",
        )
        button.pack(fill="x", padx=10, pady=2)
        self.nav_buttons[name] = button

    def _clear_content(self):
        for child in self.content.winfo_children():
            child.destroy()

    def _page_header(self, title, subtitle):
        header = tk.Frame(self.content, bg=COLORS["bg"])
        header.pack(fill="x", padx=34, pady=(28, 22))
        tk.Label(
            header,
            text=title,
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=(FONT, 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text=subtitle,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(5, 0))
        return header

    def _card(self, parent, bg=None):
        return tk.Frame(
            parent,
            bg=bg or COLORS["panel"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )

    def _button(self, parent, text, command, primary=False):
        background = COLORS["accent"] if primary else COLORS["panel_alt"]
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=background,
            fg=COLORS["text"],
            activebackground=COLORS["accent_hover"] if primary else COLORS["border"],
            activeforeground=COLORS["text"],
            relief="flat",
            bd=0,
            font=(FONT, 10, "bold"),
            padx=20,
            pady=12,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=COLORS["accent"] if primary else COLORS["border"],
        )

    def show_page(self, name):
        self.current_page = name
        for nav_name, button in self.nav_buttons.items():
            if nav_name == name:
                button.configure(
                    bg=COLORS["accent_soft"],
                    fg=COLORS["text"],
                    highlightthickness=0,
                    font=(FONT, 10, "bold"),
                )
            else:
                button.configure(
                    bg=COLORS["sidebar"],
                    fg=COLORS["muted"],
                    font=(FONT, 10, "normal"),
                )

        self._clear_content()
        page_builders = {
            "Dashboard": self._dashboard_page,
            "Scan Center": self._scan_page,
            "Quarantine": self._quarantine_page,
            "Settings": self._settings_page,
            "About": self._about_page,
        }
        page_builders[name]()

    def _engine_status_text(self):
        if scan_engine is None:
            return "●  Engine import failed"
        try:
            status = scan_engine.get_engine_status()
        except Exception:
            return "●  Engine error"
        if status.get("hash_database") == "loaded":
            return "●  Engine connected"
        if status.get("hash_database") == "empty":
            return "●  Engine connected · no definitions"
        return "●  Engine needs attention"

    def _start_quick_scan(self):
        self._start_scan("Quick Scan")

    def _start_full_scan(self):
        self._start_scan("Full Scan")

    def _start_scan(self, scan_type, roots=None):
        if scan_engine is None:
            messagebox.showerror(
                "Scanning engine unavailable",
                f"The scanning engine could not be imported.\n\n{ENGINE_IMPORT_ERROR}",
                parent=self.root,
            )
            return

        if self.scan_running:
            messagebox.showinfo(
                "Scan already running",
                "A scan is already running.",
                parent=self.root,
            )
            return

        self.show_page("Scan Center")
        self.scan_running = True
        self.scan_cancel_event = threading.Event()
        self.scan_status_var.set(f"{scan_type} in progress…")
        self.scan_detail_var.set("Files scanned: 0 · Preparing scan…")
        if self.cancel_scan_button is not None and self.cancel_scan_button.winfo_exists():
            self.cancel_scan_button.configure(state="normal")

        def worker():
            last_progress_time = [0.0]

            def report_progress(scanned, result):
                now = time.monotonic()
                important_result = result.status in {"known_threat", "error"}
                if scanned == 1 or scanned % 25 == 0 or important_result or now - last_progress_time[0] >= 0.25:
                    self.scan_queue.put(("progress", scanned, result))
                    last_progress_time[0] = now

            try:
                if scan_type == "Quick Scan":
                    summary = scan_engine.quick_scan(
                        progress_callback=report_progress,
                        cancel_event=self.scan_cancel_event,
                    )
                else:
                    summary = scan_engine.full_scan(
                        roots=roots,
                        progress_callback=report_progress,
                        cancel_event=self.scan_cancel_event,
                    )
                self.scan_queue.put(("complete", summary))
            except Exception as exc:
                self.scan_queue.put(("failure", str(exc)))

        self.scan_thread = threading.Thread(
            target=worker,
            name="StasivynScanWorker",
            daemon=True,
        )
        self.scan_thread.start()
        self.root.after(100, self._poll_scan_queue)

    def _cancel_scan(self):
        if self.scan_running and self.scan_cancel_event is not None:
            self.scan_cancel_event.set()
            self.scan_status_var.set("Cancellation requested…")
            self.scan_detail_var.set("The current file will finish before scanning stops.")

    def _poll_scan_queue(self):
        if not self.root.winfo_exists():
            return

        try:
            while True:
                message = self.scan_queue.get_nowait()
                kind = message[0]

                if kind == "progress":
                    _, scanned, result = message
                    path_text = result.path
                    if len(path_text) > 95:
                        path_text = "…" + path_text[-92:]
                    self.scan_status_var.set("Scanning files…")
                    self.scan_detail_var.set(
                        f"Files scanned: {scanned} · Current file: {path_text}"
                    )

                elif kind == "complete":
                    summary = message[1]
                    self.scan_running = False
                    self.last_scan_summary = summary
                    self.last_scan = datetime.now().strftime("%Y-%m-%d %H:%M")
                    if self.cancel_scan_button is not None and self.cancel_scan_button.winfo_exists():
                        self.cancel_scan_button.configure(state="disabled")

                    ending = "cancelled" if summary.cancelled else "completed"
                    self.scan_status_var.set(f"{summary.scan_type} {ending}.")
                    self.scan_detail_var.set(
                        f"Files scanned: {summary.scanned} · Known threats: "
                        f"{summary.known_threats} · Errors: {summary.errors}"
                    )
                    self._show_scan_summary(summary)

                elif kind == "failure":
                    self.scan_running = False
                    if self.cancel_scan_button is not None and self.cancel_scan_button.winfo_exists():
                        self.cancel_scan_button.configure(state="disabled")
                    self.scan_status_var.set("Scan failed.")
                    self.scan_detail_var.set(message[1])
                    messagebox.showerror(
                        "Scan failed", message[1], parent=self.root
                    )
        except queue.Empty:
            pass

        if self.scan_running:
            self.root.after(100, self._poll_scan_queue)

    def _show_scan_summary(self, summary):
        threat_results = [
            result for result in summary.results
            if result.status == "known_threat"
        ]
        lines = [
            f"Scan: {summary.scan_type}",
            f"Unique files inspected: {summary.scanned}",
            f"Known hash matches: {summary.known_threats}",
            f"Inspection errors: {summary.errors}",
            f"Running processes found: {summary.processes_found}",
            f"Registry entries checked: {summary.registry_entries_checked}",
            f"Cancelled: {'Yes' if summary.cancelled else 'No'}",
            "",
            "File candidates by category:",
        ]
        for category, count in summary.category_counts.items():
            lines.append(f"{category}: {count}")
        if summary.warnings:
            lines.extend(["", f"Warnings ({len(summary.warnings)}):"])
            lines.extend(f"• {warning}" for warning in summary.warnings[:8])
            if len(summary.warnings) > 8:
                lines.append(f"…and {len(summary.warnings) - 8} more.")
        lines.extend([
            "",
            "No files were moved, deleted, or quarantined.",
            "A file with no matching hash is UNKNOWN, not proven safe.",
            "Process scanning checks executable file paths, not process memory.",
            "Registry scanning checks selected startup and service entries read-only.",
        ])
        if threat_results:
            lines.extend(["", "Matching files:"])
            for result in threat_results[:8]:
                lines.append(f"• {result.threat_name or 'Known threat'}: {result.path}")
            if len(threat_results) > 8:
                lines.append(f"…and {len(threat_results) - 8} more.")

        details = "\n".join(lines)
        if threat_results:
            messagebox.showwarning("Scan finished — matches found", details, parent=self.root)
        else:
            messagebox.showinfo("Scan finished", details, parent=self.root)

    def _dashboard_page(self):
        self._page_header("Dashboard", "Computer security overview.")
        wrap = tk.Frame(self.content, bg=COLORS["bg"])
        wrap.pack(fill="both", expand=True, padx=34, pady=(0, 28))

        status_card = self._card(wrap)
        status_card.pack(fill="x", pady=(0, 16))
        inner = tk.Frame(status_card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=22, pady=22)

        tk.Label(
            inner,
            text=(
                "Scanning engine connected."
                if scan_engine is not None
                else "Scanning engine could not be loaded."
            ),
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 18, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text=(
                scan_engine.get_engine_status().get("message", "Engine status unavailable.")
                if scan_engine is not None
                else str(ENGINE_IMPORT_ERROR)
            ),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(8, 14))

        details = tk.Frame(inner, bg=COLORS["panel"])
        details.pack(anchor="w")
        tk.Label(
            details,
            text=f"Last scan: {self.last_scan}",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(side="left")
        tk.Label(
            details,
            text=(
                "   •   Definitions: "
                + str(scan_engine.get_engine_status().get("hash_database", "unavailable"))
                if scan_engine is not None
                else "   •   Engine: Not connected"
            ),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(side="left")

        scan_row = tk.Frame(wrap, bg=COLORS["bg"])
        scan_row.pack(fill="x", pady=(0, 16))
        self._button(
            scan_row,
            "⌕   Quick Scan",
            self._start_quick_scan,
            True,
        ).pack(side="left", padx=(0, 12))
        self._button(
            scan_row,
            "▱   Full Scan",
            self._start_full_scan,
        ).pack(side="left")
        self._button(
            scan_row,
            "Open Scan Center  →",
            lambda: self.show_page("Scan Center"),
        ).pack(side="right")

        metrics = tk.Frame(wrap, bg=COLORS["bg"])
        metrics.pack(fill="x", pady=(0, 16))
        for column in range(4):
            metrics.grid_columnconfigure(column, weight=1, uniform="metric")

        threat_count = (
            str(self.last_scan_summary.known_threats)
            if self.last_scan_summary is not None else "—"
        )
        definition_count = "Unavailable"
        if scan_engine is not None:
            engine_status = scan_engine.get_engine_status()
            definition_count = (
                str(engine_status.get("definition_count", "0"))
                if engine_status.get("hash_database") == "loaded" else "0"
            )
        self._metric(metrics, 0, "THREATS FOUND", threat_count, "Last scan matches", "◈")
        self._metric(metrics, 1, "LAST SCAN", self.last_scan, "Most recent scan", "↺")
        self._metric(metrics, 2, "DEFINITIONS", definition_count, "SHA-256 signatures", "▤")
        self._metric(metrics, 3, "PROTECTION", "Not active", "Real-time monitoring pending", "⌁")

        activity_card = self._card(wrap)
        activity_card.pack(fill="both", expand=True)
        tk.Label(
            activity_card,
            text="Recent activity",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 11, "bold"),
        ).pack(anchor="w", padx=18, pady=(14, 8))
        tk.Frame(activity_card, bg=COLORS["border"], height=1).pack(fill="x", padx=18)
        tk.Label(
            activity_card,
            text="No activity recorded.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", padx=18, pady=18)

    def _metric(self, parent, column, heading, value, caption, symbol):
        card = self._card(parent)
        card.grid(
            row=0,
            column=column,
            sticky="nsew",
            padx=(0 if column == 0 else 7, 7 if column < 3 else 0),
        )
        tk.Label(
            card,
            text=symbol,
            bg=COLORS["panel"],
            fg=COLORS["accent"],
            font=(FONT, 17, "bold"),
        ).pack(anchor="w", padx=15, pady=(12, 5))
        tk.Label(
            card,
            text=heading,
            bg=COLORS["panel"],
            fg=COLORS["muted2"],
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=15)
        tk.Label(
            card,
            text=value,
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 13, "bold"),
        ).pack(anchor="w", padx=15, pady=(4, 0))
        tk.Label(
            card,
            text=caption,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 8),
        ).pack(anchor="w", padx=15, pady=(3, 12))

    def _scan_page(self):
        self._page_header("Scan Center", "Quick Scan checks common folders. Full Scan checks additional Windows locations.")
        wrap = tk.Frame(self.content, bg=COLORS["bg"])
        wrap.pack(fill="both", expand=True, padx=34, pady=(0, 30))

        card = self._card(wrap)
        card.pack(fill="x", pady=(0, 16))
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=22, pady=22)
        tk.Label(
            inner,
            text="Start a scan",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 15, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text=(
                "Quick Scan checks Downloads, Desktop and temporary files. Full Scan also checks AppData, running process executable paths and selected Windows Registry startup/service entries."
                if scan_engine is not None
                else "The scanning engine could not be loaded. Check the project files."
            ),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
            wraplength=880,
            justify="left",
        ).pack(anchor="w", pady=(7, 18))

        actions = tk.Frame(inner, bg=COLORS["panel"])
        actions.pack(anchor="w")
        self._button(
            actions,
            "⌕   Quick Scan",
            self._start_quick_scan,
            True,
        ).pack(side="left", padx=(0, 12))
        self._button(
            actions,
            "▱   Full Scan",
            self._start_full_scan,
        ).pack(side="left")
        self.cancel_scan_button = self._button(
            actions,
            "Cancel Scan",
            self._cancel_scan,
        )
        self.cancel_scan_button.pack(side="left", padx=(12, 0))
        self.cancel_scan_button.configure(
            state="normal" if self.scan_running else "disabled"
        )

        state = self._card(wrap)
        state.pack(fill="x")
        state_inner = tk.Frame(state, bg=COLORS["panel"])
        state_inner.pack(fill="x", padx=22, pady=20)
        tk.Label(
            state_inner,
            text="Scan status",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
            state_inner,
            textvariable=self.scan_status_var,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(10, 0))
        tk.Label(
            state_inner,
            textvariable=self.scan_detail_var,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
            wraplength=900,
            justify="left",
        ).pack(anchor="w", pady=(5, 0))
        tk.Label(
            state_inner,
            text=self.engine_status_var.get(),
            bg=COLORS["panel"],
            fg=COLORS["green"] if scan_engine is not None else COLORS["yellow"],
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(5, 0))

    def _quarantine_page(self):
        self._page_header("Quarantine", "File isolation is not implemented yet.")
        wrap = tk.Frame(self.content, bg=COLORS["bg"])
        wrap.pack(fill="both", expand=True, padx=34, pady=(0, 30))
        card = self._card(wrap)
        card.pack(fill="x")
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=24, pady=28)
        tk.Label(
            inner,
            text="Quarantine is not implemented yet",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 15, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text="Scan results can identify matching files, but this build does not move, delete, or isolate them.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(8, 0))

    def _settings_page(self):
        self._page_header("Settings", "Application and protection configuration.")
        wrap = tk.Frame(self.content, bg=COLORS["bg"])
        wrap.pack(fill="both", expand=True, padx=34, pady=(0, 30))
        card = self._card(wrap)
        card.pack(fill="x", pady=(0, 16))
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=22, pady=20)

        tk.Label(
            inner,
            text="Protection engine",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 12, "bold"),
        ).pack(anchor="w", pady=(0, 5))
        tk.Label(
            inner,
            text=("Scanner connected" if scan_engine is not None else "Scanner unavailable"),
            bg=COLORS["panel"],
            fg=COLORS["green"] if scan_engine is not None else COLORS["yellow"],
            font=(FONT, 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text="Real-time file monitoring is not implemented yet. Scanning is currently started manually.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 8),
        ).pack(anchor="w", pady=(5, 16))

        tk.Frame(inner, bg=COLORS["border"], height=1).pack(fill="x", pady=(0, 15))
        tk.Label(
            inner,
            text="Application",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 12, "bold"),
        ).pack(anchor="w", pady=(0, 5))
        tk.Label(
            inner,
            text="Startup and notification preferences have not been configured.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w")

    def _about_page(self):
        self._page_header("About", "Application information.")
        wrap = tk.Frame(self.content, bg=COLORS["bg"])
        wrap.pack(fill="both", expand=True, padx=34, pady=(0, 30))
        card = self._card(wrap)
        card.pack(fill="x")
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=24, pady=24)

        tk.Label(
            inner,
            text="Stasivyn Security",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 17, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text="Computer security application",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(5, 18))

        engine_label = "Unavailable"
        if scan_engine is not None:
            engine_status = scan_engine.get_engine_status()
            engine_label = (
                f"Connected · {engine_status.get('definition_count', 0):,} hashes"
                if engine_status.get("hash_database") == "loaded"
                else "Connected · definitions unavailable"
            )

        for label, value in [
            ("Version", "0.1.0"),
            ("Engine", engine_label),
            ("Color theme", "Crimson  #BB1330"),
            ("Interface", "Python + Tkinter"),
        ]:
            row = tk.Frame(inner, bg=COLORS["panel"])
            row.pack(fill="x", pady=5)
            tk.Label(
                row,
                text=label,
                bg=COLORS["panel"],
                fg=COLORS["muted"],
                font=(FONT, 9),
            ).pack(side="left")
            tk.Label(
                row,
                text=value,
                bg=COLORS["panel"],
                fg=COLORS["text"],
                font=(FONT, 9, "bold"),
            ).pack(side="right")

        tk.Frame(inner, bg=COLORS["border"], height=1).pack(fill="x", pady=15)
        tk.Label(
            inner,
            text="Detection capabilities",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=(FONT, 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text="Scanning uses exact SHA-256 hash matching. A file with no matching hash remains unknown, not proven safe. Quarantine and real-time protection are not implemented yet.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9),
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))


def main():
    root = tk.Tk()
    StasivynSecurity(root)
    root.mainloop()


if __name__ == "__main__":
    main()
