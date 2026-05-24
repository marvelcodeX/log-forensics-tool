"""
detail.py
---------
Detail drawer that appears on the right side when a finding is clicked.
Shows full context: description, geo info, raw log lines.
"""

import customtkinter as ctk
from core.report import SEVERITY_COLOR, TYPE_LABELS


class DetailDrawer(ctk.CTkToplevel):
    """A secondary window that shows full finding details."""

    def __init__(self, parent, C: dict):
        super().__init__(parent)
        self.C = C
        self.title("Finding Detail")
        self.geometry("560x620")
        self.resizable(True, True)
        self.configure(fg_color=C["bg"])
        self.withdraw()   # hidden until show() is called
        self._build()

    def _build(self):
        C = self.C
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Header
        self._header = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0)
        self._header.grid(row=0, column=0, sticky="ew")
        self._header.grid_columnconfigure(0, weight=1)

        self._sev_bar = ctk.CTkFrame(self._header, fg_color=C["muted"], height=4, corner_radius=0)
        self._sev_bar.grid(row=0, column=0, columnspan=2, sticky="ew")

        self._title_lbl = ctk.CTkLabel(
            self._header, text="",
            font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
            text_color=C["text"], wraplength=480, justify="left",
        )
        self._title_lbl.grid(row=1, column=0, sticky="w", padx=18, pady=(10, 4))

        self._type_lbl = ctk.CTkLabel(
            self._header, text="",
            font=ctk.CTkFont(size=11), text_color=C["muted"],
        )
        self._type_lbl.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 12))

        ctk.CTkButton(
            self._header, text="✕  Close",
            command=self.withdraw,
            width=80, height=26,
            fg_color="transparent", hover_color=C["border"],
            text_color=C["muted"],
        ).grid(row=1, column=1, padx=14, pady=8)

        # Scrollable body
        self._body = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self._body.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self._body.grid_columnconfigure(0, weight=1)

    def show(self, finding: dict):
        C   = self.C
        sev = finding["severity"]
        color = SEVERITY_COLOR.get(sev, C["muted"])

        self._sev_bar.configure(fg_color=color)
        self._title_lbl.configure(text=finding["title"])
        self._type_lbl.configure(
            text=f"{sev}  ·  {TYPE_LABELS.get(finding['type'], finding['type'])}  "
                 f"·  {finding['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if finding['timestamp'] else '—'}"
        )

        # Clear body
        for w in self._body.winfo_children():
            w.destroy()

        row = 0

        def section(title: str) -> int:
            nonlocal row
            ctk.CTkLabel(
                self._body, text=title,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=C["muted"],
            ).grid(row=row, column=0, sticky="w", padx=16, pady=(14, 2))
            row += 1
            ctk.CTkFrame(self._body, fg_color=C["border"], height=1,
                         ).grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 6))
            row += 1
            return row

        def kv(key: str, value: str, color=None):
            nonlocal row
            f = ctk.CTkFrame(self._body, fg_color="transparent")
            f.grid(row=row, column=0, sticky="ew", padx=16, pady=2)
            f.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(f, text=key + ":",
                         font=ctk.CTkFont(size=11), text_color=C["muted"],
                         width=110, anchor="w",
                         ).grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(f, text=str(value) if value else "—",
                         font=ctk.CTkFont(size=11),
                         text_color=color or C["text"],
                         anchor="w", wraplength=360, justify="left",
                         ).grid(row=0, column=1, sticky="w")
            row += 1

        # ── Overview ──────────────────────────────────────────────────────────
        section("OVERVIEW")
        kv("Severity",   sev, color)
        kv("Type",       TYPE_LABELS.get(finding["type"], finding["type"]))
        kv("Finding ID", finding["id"])
        kv("Source IP",  finding.get("source_ip") or "—")
        kv("User",       finding.get("user") or "—")

        # ── Description ───────────────────────────────────────────────────────
        section("DESCRIPTION")
        ctk.CTkLabel(
            self._body, text=finding["description"],
            font=ctk.CTkFont(size=12), text_color=C["text"],
            wraplength=500, justify="left", anchor="w",
        ).grid(row=row, column=0, sticky="w", padx=16, pady=(0, 4))
        row += 1

        # ── Geo info ──────────────────────────────────────────────────────────
        geo = finding["extra"].get("geo")
        if geo and not geo.get("error"):
            section("GEOLOCATION")
            kv("Country", geo.get("country", ""))
            kv("Region",  geo.get("region", ""))
            kv("City",    geo.get("city", ""))
            kv("ISP",     geo.get("isp", ""))
            lat = geo.get("lat", 0)
            lon = geo.get("lon", 0)
            if lat or lon:
                kv("Coordinates", f"{lat}, {lon}")

        # ── Extra fields ──────────────────────────────────────────────────────
        extra_skip = {"geo", "geo_summary"}
        extra_data = {k: v for k, v in finding["extra"].items() if k not in extra_skip}
        if extra_data:
            section("EXTRA DETAILS")
            for k, v in extra_data.items():
                if isinstance(v, list):
                    v = ", ".join(str(i) for i in v[:10])
                kv(k.replace("_", " ").title(), str(v))

        # ── Raw log lines ─────────────────────────────────────────────────────
        raw_lines = finding.get("raw_lines", [])
        if raw_lines:
            section(f"RAW LOG LINES ({len(raw_lines)} shown)")
            box = ctk.CTkTextbox(
                self._body,
                fg_color=C["surface"],
                text_color="#7ee787",
                font=ctk.CTkFont(family="Courier New", size=10),
                corner_radius=6,
                height=min(180, len(raw_lines) * 18 + 20),
                state="normal",
                wrap="none",
            )
            box.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 16))
            for line in raw_lines:
                box.insert("end", line + "\n")
            box.configure(state="disabled")
            row += 1

        self.deiconify()
        self.lift()
        self.focus_force()