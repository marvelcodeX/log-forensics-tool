"""
findings.py
-----------
Filterable findings table. Rows are clickable and open the detail drawer.
"""

import customtkinter as ctk
from core.report import Report, SEVERITY_COLOR, TYPE_LABELS


class FindingsPanel(ctk.CTkFrame):
    def __init__(self, parent, C: dict, on_select):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.C = C
        self.on_select = on_select
        self._report: Report | None = None
        self._severity_var = ctk.StringVar(value="All severities")
        self._type_var = ctk.StringVar(value="All types")
        self._build()

    def _build(self):
        C = self.C
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        controls = ctk.CTkFrame(
            self,
            fg_color=C["surface"],
            corner_radius=8,
            border_color=C["border"],
            border_width=1,
        )
        controls.grid(row=0, column=0, sticky="ew", padx=2, pady=(2, 8))
        controls.grid_columnconfigure(4, weight=1)

        ctk.CTkLabel(
            controls,
            text="Severity",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).grid(row=0, column=0, padx=(14, 6), pady=10)

        self._severity_menu = ctk.CTkOptionMenu(
            controls,
            variable=self._severity_var,
            values=["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            command=lambda _: self._render_rows(),
            fg_color=C["border"],
            button_color=C["accent"],
            button_hover_color="#4493e0",
            width=150,
        )
        self._severity_menu.grid(row=0, column=1, padx=(0, 14), pady=10)

        ctk.CTkLabel(
            controls,
            text="Type",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).grid(row=0, column=2, padx=(0, 6), pady=10)

        self._type_menu = ctk.CTkOptionMenu(
            controls,
            variable=self._type_var,
            values=["All types"],
            command=lambda _: self._render_rows(),
            fg_color=C["border"],
            button_color=C["accent"],
            button_hover_color="#4493e0",
            width=180,
        )
        self._type_menu.grid(row=0, column=3, padx=(0, 14), pady=10)

        self._count_label = ctk.CTkLabel(
            controls,
            text="No findings",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        )
        self._count_label.grid(row=0, column=4, sticky="e", padx=14, pady=10)

        header = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        header.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 4))
        header.grid_columnconfigure(2, weight=1)

        for col, (text, width) in enumerate(
            [
                ("Severity", 100),
                ("Type", 140),
                ("Finding", 320),
                ("Source", 130),
                ("User", 110),
                ("Time", 150),
            ]
        ):
            ctk.CTkLabel(
                header,
                text=text,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=C["muted"],
                width=width,
                anchor="w",
            ).grid(row=0, column=col, sticky="ew", padx=4)

        self._rows = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
        )
        self._rows.grid(row=2, column=0, sticky="nsew", padx=2)
        self._rows.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._rows,
            text="Findings will appear after loading a log file.",
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
        ).grid(row=0, column=0, pady=40)

    def load(self, report: Report):
        self._report = report
        types = ["All types"] + [
            TYPE_LABELS.get(finding_type, finding_type)
            for finding_type in sorted(report.type_counts.keys())
        ]
        self._type_menu.configure(values=types)
        self._severity_var.set("All severities")
        self._type_var.set("All types")
        self._render_rows()

    def _filtered_findings(self) -> list[dict]:
        if not self._report:
            return []

        severity = self._severity_var.get()
        type_label = self._type_var.get()
        findings = self._report.findings_by_severity()

        if severity != "All severities":
            findings = [f for f in findings if f["severity"] == severity]
        if type_label != "All types":
            findings = [
                f for f in findings
                if TYPE_LABELS.get(f["type"], f["type"]) == type_label
            ]

        return findings

    def _render_rows(self):
        C = self.C
        for widget in self._rows.winfo_children():
            widget.destroy()

        findings = self._filtered_findings()
        total = self._report.total_findings if self._report else 0
        self._count_label.configure(text=f"{len(findings)} of {total} findings")

        if not findings:
            ctk.CTkLabel(
                self._rows,
                text="No findings match the current filters.",
                font=ctk.CTkFont(size=12),
                text_color=C["muted"],
            ).grid(row=0, column=0, pady=30)
            return

        for row_index, finding in enumerate(findings):
            self._add_row(row_index, finding)

    def _add_row(self, row_index: int, finding: dict):
        C = self.C
        severity = finding["severity"]
        color = SEVERITY_COLOR.get(severity, C["muted"])
        timestamp = (
            finding["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            if finding["timestamp"]
            else "-"
        )

        row = ctk.CTkFrame(
            self._rows,
            fg_color=C["surface"] if row_index % 2 == 0 else "#111820",
            border_color=C["border"],
            border_width=1,
            corner_radius=6,
        )
        row.grid(row=row_index, column=0, sticky="ew", pady=3)
        row.grid_columnconfigure(2, weight=1)

        values = [
            (severity, 100, color, "bold"),
            (TYPE_LABELS.get(finding["type"], finding["type"]), 140, C["text"], "normal"),
            (finding["title"], 320, C["text"], "normal"),
            (finding.get("source_ip") or "-", 130, C["muted"], "normal"),
            (finding.get("user") or "-", 110, C["muted"], "normal"),
            (timestamp, 150, C["muted"], "normal"),
        ]

        for col, (text, width, text_color, weight) in enumerate(values):
            label = ctk.CTkLabel(
                row,
                text=text,
                font=ctk.CTkFont(size=11, weight=weight),
                text_color=text_color,
                width=width,
                anchor="w",
            )
            label.grid(row=0, column=col, sticky="ew", padx=4, pady=8)
            label.bind("<Button-1>", lambda _event, f=finding: self.on_select(f))

        row.bind("<Button-1>", lambda _event, f=finding: self.on_select(f))
