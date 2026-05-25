"""
app.py
------
Main application window. Hosts the sidebar, tab views, and
wires all panels together.
"""

import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.parser    import parse_log_file
from core.detectors import run_all_detectors
from core.report    import Report

from ui.sidebar   import SidebarPanel
from ui.findings  import FindingsPanel
from ui.timeline  import TimelinePanel
from ui.detail    import DetailDrawer

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ────────────────────────────────────────────────────────────────────
C = {
    "bg":      "#0d1117",
    "surface": "#161b22",
    "border":  "#30363d",
    "accent":  "#58a6ff",
    "green":   "#3fb950",
    "red":     "#f85149",
    "amber":   "#d29922",
    "text":    "#e6edf3",
    "muted":   "#8b949e",
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Log Forensics Tool")
        self.geometry("1280x780")
        self.minsize(1000, 650)
        self.configure(fg_color=C["bg"])

        self.report: Report | None = None
        self._build()

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top bar
        topbar = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0, height=54)
        topbar.grid(row=0, column=0, columnspan=2, sticky="ew")
        topbar.grid_propagate(False)

        ctk.CTkLabel(
            topbar,
            text="🔬  Log Forensics Tool",
            font=ctk.CTkFont(family="Courier New", size=17, weight="bold"),
            text_color=C["accent"],
        ).pack(side="left", padx=22, pady=14)

        self.status_lbl = ctk.CTkLabel(
            topbar, text="No file loaded",
            font=ctk.CTkFont(size=12), text_color=C["muted"],
        )
        self.status_lbl.pack(side="right", padx=22)

        self.risk_badge = ctk.CTkLabel(
            topbar, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["bg"],
            fg_color=C["muted"],
            corner_radius=6,
            width=90, height=26,
        )
        self.risk_badge.pack(side="right", padx=(0, 10), pady=14)

        # Sidebar
        self.sidebar = SidebarPanel(self, C, on_load=self._load_file)
        self.sidebar.grid(row=1, column=0, sticky="ns")

        # Main area
        main = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        main.grid(row=1, column=1, sticky="nsew")
        main.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Tab view
        self.tabs = ctk.CTkTabview(
            main,
            fg_color=C["surface"],
            segmented_button_fg_color=C["border"],
            segmented_button_selected_color=C["accent"],
            segmented_button_selected_hover_color="#4493e0",
            segmented_button_unselected_color=C["border"],
            segmented_button_unselected_hover_color="#3d444d",
            text_color=C["text"],
            border_color=C["border"], border_width=1,
            corner_radius=10,
        )
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=16, pady=12)

        findings_tab  = self.tabs.add("🚨  Findings")
        timeline_tab  = self.tabs.add("📅  Timeline")

        for tab in (findings_tab, timeline_tab):
            tab.grid_rowconfigure(0, weight=1)
            tab.grid_columnconfigure(0, weight=1)

        self.findings_panel = FindingsPanel(findings_tab, C, on_select=self._show_detail)
        self.findings_panel.grid(row=0, column=0, sticky="nsew")

        self.timeline_panel = TimelinePanel(timeline_tab, C, on_select=self._show_detail)
        self.timeline_panel.grid(row=0, column=0, sticky="nsew")

        # Detail drawer (right side, hidden initially)
        self.detail_drawer = DetailDrawer(self, C)

        # Progress overlay
        self._progress_frame = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=12)
        self._progress_lbl   = ctk.CTkLabel(
            self._progress_frame, text="Analyzing…",
            font=ctk.CTkFont(size=14), text_color=C["text"],
        )
        self._progress_lbl.pack(pady=(30, 8), padx=40)
        self._progress_bar = ctk.CTkProgressBar(
            self._progress_frame, fg_color=C["border"], progress_color=C["accent"], width=280,
        )
        self._progress_bar.pack(pady=(0, 30), padx=40)
        self._progress_bar.set(0)

    # ── File loading ───────────────────────────────────────────────────────────
    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open log file",
            filetypes=[("Log files", "*.log *.txt *.access *.out"), ("All files", "*.*")],
        )
        if not path:
            return
        self._show_progress(path)
        threading.Thread(target=self._analyse, args=(path,), daemon=True).start()

    def _show_progress(self, path: str):
        self._progress_bar.start()
        self._progress_frame.place(relx=0.5, rely=0.45, anchor="center")
        self._progress_lbl.configure(text=f"Parsing {path.split('/')[-1]}…")
        self.status_lbl.configure(text="Analyzing…", text_color=C["amber"])

    def _hide_progress(self):
        self._progress_bar.stop()
        self._progress_frame.place_forget()

    def _analyse(self, path: str):
        try:
            entries, fmt = parse_log_file(path)
            findings     = run_all_detectors(entries, fmt)
            report       = Report(path, entries, findings, fmt)
            self.after(0, self._on_report_ready, report)
        except Exception as exc:
            self.after(0, self._on_error, str(exc))

    def _on_report_ready(self, report: Report):
        self.report = report
        self._hide_progress()
        self.sidebar.load(report)
        self.findings_panel.load(report)
        self.timeline_panel.load(report)

        # Risk badge
        label = report.risk_label()
        badge_colors = {
            "CRITICAL": C["red"],    "HIGH": C["amber"],
            "MEDIUM":   C["accent"], "LOW":  C["green"], "CLEAN": C["muted"],
        }
        self.risk_badge.configure(
            text=f" {label} ", fg_color=badge_colors.get(label, C["muted"]),
        )

        fname = report.filepath.split("/")[-1].split("\\")[-1]
        self.status_lbl.configure(
            text=f"{fname}  ·  {report.total_lines} lines  ·  {report.total_findings} findings",
            text_color=C["text"],
        )

    def _on_error(self, msg: str):
        self._hide_progress()
        self.status_lbl.configure(text="Error loading file", text_color=C["red"])
        messagebox.showerror("Parse Error", msg)

    # ── Detail drawer ──────────────────────────────────────────────────────────
    def _show_detail(self, finding: dict):
        self.detail_drawer.show(finding)
