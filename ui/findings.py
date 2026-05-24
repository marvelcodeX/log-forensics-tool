"""
sidebar.py
----------
Left sidebar: file loader button, scan stats, top IPs.
"""

import customtkinter as ctk
from core.report import Report, SEVERITY_COLOR, TYPE_LABELS


class SidebarPanel(ctk.CTkFrame):
    def __init__(self, parent, C: dict, on_load):
        super().__init__(parent, fg_color=C["surface"], corner_radius=0, width=210)
        self.grid_propagate(False)
        self.C        = C
        self.on_load  = on_load
        self._build()

    def _build(self):
        C = self.C
        self.grid_columnconfigure(0, weight=1)

        # Logo area
        ctk.CTkLabel(
            self, text="FORENSICS",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(22, 2))

        ctk.CTkButton(
            self,
            text="  📂  Load Log File",
            command=self.on_load,
            fg_color=C["accent"],
            hover_color="#4493e0",
            text_color="#000000",
            font=ctk.CTkFont(weight="bold"),
            height=38, corner_radius=8,
        ).grid(row=1, column=0, padx=12, pady=(4, 18), sticky="ew")

        self._divider(row=2)

        # Stats section
        ctk.CTkLabel(
            self, text="SCAN SUMMARY",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=C["muted"],
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(12, 6))

        self._stat_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._stat_frame.grid(row=4, column=0, sticky="ew", padx=12)
        self._stat_frame.grid_columnconfigure(0, weight=1)

        self._stat_labels: dict[str, ctk.CTkLabel] = {}
        for i, (key, label, color) in enumerate([
            ("total_lines",    "Lines parsed",  C["muted"]),
            ("total_findings", "Findings",      C["text"]),
            ("CRITICAL",       "Critical",      SEVERITY_COLOR["CRITICAL"]),
            ("HIGH",           "High",          SEVERITY_COLOR["HIGH"]),
            ("MEDIUM",         "Medium",        SEVERITY_COLOR["MEDIUM"]),
        ]):
            row_f = ctk.CTkFrame(self._stat_frame, fg_color="transparent")
            row_f.grid(row=i, column=0, sticky="ew", pady=2)
            row_f.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(row_f, text=label,
                         font=ctk.CTkFont(size=11), text_color=C["muted"],
                         anchor="w").grid(row=0, column=0, sticky="w")
            val = ctk.CTkLabel(row_f, text="—",
                               font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                               text_color=color, anchor="e")
            val.grid(row=0, column=1, sticky="e")
            self._stat_labels[key] = val

        self._divider(row=5)

        # Top IPs
        ctk.CTkLabel(
            self, text="TOP SOURCE IPs",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=C["muted"],
        ).grid(row=6, column=0, sticky="w", padx=16, pady=(12, 6))

        self._ip_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent", height=160,
        )
        self._ip_frame.grid(row=7, column=0, sticky="ew", padx=12)
        self._ip_frame.grid_columnconfigure(0, weight=1)

        self._divider(row=8)

        # Format badge
        ctk.CTkLabel(
            self, text="FORMAT",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=C["muted"],
        ).grid(row=9, column=0, sticky="w", padx=16, pady=(12, 4))

        self._fmt_label = ctk.CTkLabel(
            self, text="—",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=C["text"],
        )
        self._fmt_label.grid(row=10, column=0, sticky="w", padx=20, pady=(0, 20))

    def _divider(self, row: int):
        ctk.CTkFrame(self, fg_color=self.C["border"], height=1
                     ).grid(row=row, column=0, sticky="ew", padx=12, pady=2)

    def load(self, report: Report):
        C = self.C
        # Update stat labels
        self._stat_labels["total_lines"].configure(text=str(report.total_lines))
        self._stat_labels["total_findings"].configure(text=str(report.total_findings))
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            cnt = report.severity_counts.get(sev, 0)
            self._stat_labels[sev].configure(text=str(cnt))

        # Top IPs
        for w in self._ip_frame.winfo_children():
            w.destroy()
        for i, (ip, cnt) in enumerate(report.top_ips[:8]):
            row_f = ctk.CTkFrame(self._ip_frame, fg_color="transparent")
            row_f.grid(row=i, column=0, sticky="ew", pady=1)
            row_f.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row_f, text=ip,
                         font=ctk.CTkFont(family="Courier New", size=10),
                         text_color=C["text"], anchor="w",
                         ).grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(row_f, text=str(cnt),
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=C["amber"], anchor="e",
                         ).grid(row=0, column=1, sticky="e")

        self._fmt_label.configure(text=report.log_format.upper())