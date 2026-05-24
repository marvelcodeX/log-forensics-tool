"""
timeline.py
-----------
Visual timeline panel. Draws events as dots on a horizontal time axis.
Each dot is clickable and opens the detail drawer.

Layout:
  ┌─────────────────────────────────────────────────────┐
  │  [severity legend]                                  │
  │                                                     │
  │  ────●──────●──────●──────────●──── (time axis)    │
  │      │      │                                       │
  │  [label] [label]                                    │
  │                                                     │
  │  [scrollable event list below axis]                 │
  └─────────────────────────────────────────────────────┘
"""

import tkinter as tk
import customtkinter as ctk
from datetime import datetime, timedelta
from core.report import Report, SEVERITY_COLOR, TYPE_LABELS

DOT_R   = 7    # dot radius
AXIS_Y  = 80   # y-position of the timeline axis
PAD_X   = 60   # left/right padding
LANE_H  = 30   # vertical spacing between lanes (for stacked events)


class TimelinePanel(ctk.CTkFrame):
    def __init__(self, parent, C: dict, on_select):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.C         = C
        self.on_select = on_select
        self._findings: list[dict] = []
        self._dot_map: dict[int, dict] = {}   # canvas item id → finding
        self._build()

    def _build(self):
        C = self.C
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Legend ─────────────────────────────────────────────────────────────
        legend = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=8,
                               border_color=C["border"], border_width=1)
        legend.grid(row=0, column=0, sticky="ew", padx=2, pady=(2, 8))

        ctk.CTkLabel(legend, text="Severity:",
                     font=ctk.CTkFont(size=11), text_color=C["muted"],
                     ).pack(side="left", padx=(14, 8), pady=8)

        for sev, color in SEVERITY_COLOR.items():
            ctk.CTkFrame(legend, fg_color=color, width=12, height=12, corner_radius=6,
                         ).pack(side="left", padx=(0, 3), pady=8)
            ctk.CTkLabel(legend, text=sev,
                         font=ctk.CTkFont(size=10), text_color=color,
                         ).pack(side="left", padx=(0, 10), pady=8)

        ctk.CTkLabel(legend, text="← Click a dot to inspect",
                     font=ctk.CTkFont(size=10), text_color=C["muted"],
                     ).pack(side="right", padx=14, pady=8)

        # ── Paned: canvas on top, list on bottom ───────────────────────────────
        pane = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        pane.grid(row=1, column=0, sticky="nsew")
        pane.grid_rowconfigure(1, weight=1)
        pane.grid_columnconfigure(0, weight=1)

        # Canvas for timeline drawing
        self._canvas_frame = ctk.CTkFrame(pane, fg_color=C["surface"], corner_radius=8,
                                           border_color=C["border"], border_width=1,
                                           height=200)
        self._canvas_frame.grid(row=0, column=0, sticky="ew", padx=2, pady=(0, 8))
        self._canvas_frame.grid_propagate(False)
        self._canvas_frame.grid_columnconfigure(0, weight=1)
        self._canvas_frame.grid_rowconfigure(0, weight=1)

        self._canvas = tk.Canvas(
            self._canvas_frame,
            bg=C["surface"], highlightthickness=0, cursor="hand2",
        )
        self._canvas.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self._canvas.bind("<Button-1>", self._on_canvas_click)
        self._canvas.bind("<Configure>", lambda e: self._redraw())

        # Scrollable event list below the canvas
        self._list_scroll = ctk.CTkScrollableFrame(
            pane, fg_color="transparent", corner_radius=0,
        )
        self._list_scroll.grid(row=1, column=0, sticky="nsew", padx=2)
        self._list_scroll.grid_columnconfigure(0, weight=1)

        self._empty = ctk.CTkLabel(
            self._list_scroll,
            text="Timeline will appear after loading a log file.",
            font=ctk.CTkFont(size=13), text_color=C["muted"],
        )
        self._empty.grid(row=0, column=0, pady=40)

    # ── Data ───────────────────────────────────────────────────────────────────
    def load(self, report: Report):
        self._findings = report.findings_for_timeline()
        self._redraw()
        self._build_list()

    # ── Canvas drawing ─────────────────────────────────────────────────────────
    def _redraw(self):
        C = self.C
        cv = self._canvas
        cv.delete("all")
        self._dot_map = {}

        if not self._findings:
            cv.create_text(
                cv.winfo_width() // 2, AXIS_Y,
                text="No timestamped findings to display.",
                fill=C["muted"], font=("Courier New", 11),
            )
            return

        W = cv.winfo_width()
        if W < 10:
            W = 900

        # Time range
        timestamps = [f["timestamp"] for f in self._findings if f["timestamp"]]
        if not timestamps:
            return
        t_min = min(timestamps)
        t_max = max(timestamps)
        span  = max((t_max - t_min).total_seconds(), 1)

        def x_for(ts: datetime) -> float:
            frac = (ts - t_min).total_seconds() / span
            return PAD_X + frac * (W - 2 * PAD_X)

        # Draw axis line
        cv.create_line(PAD_X - 10, AXIS_Y, W - PAD_X + 10, AXIS_Y,
                       fill=C["border"], width=2)

        # Time labels
        cv.create_text(PAD_X, AXIS_Y + 18, text=t_min.strftime("%m-%d %H:%M"),
                       fill=C["muted"], font=("Courier New", 9), anchor="w")
        cv.create_text(W - PAD_X, AXIS_Y + 18, text=t_max.strftime("%m-%d %H:%M"),
                       fill=C["muted"], font=("Courier New", 9), anchor="e")

        # Track x positions to stack overlapping dots
        x_used: dict[int, int] = {}   # rounded_x → lane count

        for f in self._findings:
            ts    = f["timestamp"]
            color = SEVERITY_COLOR.get(f["severity"], C["muted"])
            x     = x_for(ts)
            rx    = round(x / (DOT_R * 2)) * (DOT_R * 2)
            lane  = x_used.get(rx, 0)
            x_used[rx] = lane + 1
            y     = AXIS_Y - (lane * (DOT_R * 2 + 4))

            # Dot
            item = cv.create_oval(
                x - DOT_R, y - DOT_R, x + DOT_R, y + DOT_R,
                fill=color, outline=C["bg"], width=2,
            )
            self._dot_map[item] = f

            # Tick down to axis
            if lane > 0:
                cv.create_line(x, y + DOT_R, x, AXIS_Y - DOT_R,
                               fill=color, width=1, dash=(2, 3))

    def _on_canvas_click(self, event):
        items = self._canvas.find_overlapping(
            event.x - DOT_R, event.y - DOT_R,
            event.x + DOT_R, event.y + DOT_R,
        )
        for item in items:
            if item in self._dot_map:
                self.on_select(self._dot_map[item])
                return

    # ── Event list ─────────────────────────────────────────────────────────────
    def _build_list(self):
        C = self.C
        for w in self._list_scroll.winfo_children():
            w.destroy()

        if not self._findings:
            ctk.CTkLabel(
                self._list_scroll,
                text="No timestamped findings.",
                font=ctk.CTkFont(size=12), text_color=C["muted"],
            ).grid(row=0, column=0, pady=30)
            return

        for i, f in enumerate(self._findings):
            color = SEVERITY_COLOR.get(f["severity"], C["muted"])
            ts    = f["timestamp"].strftime("%Y-%m-%d  %H:%M:%S") if f["timestamp"] else "—"

            row = ctk.CTkFrame(self._list_scroll, fg_color="transparent",
                                cursor="hand2")
            row.grid(row=i, column=0, sticky="ew", pady=1)
            row.grid_columnconfigure(2, weight=1)

            # Colour stripe
            ctk.CTkFrame(row, fg_color=color, width=4, height=28,
                         corner_radius=2).grid(row=0, column=0, padx=(0, 8))

            ctk.CTkLabel(row, text=ts,
                         font=ctk.CTkFont(family="Courier New", size=10),
                         text_color=C["muted"], width=140, anchor="w",
                         ).grid(row=0, column=1)

            ctk.CTkLabel(row, text=f["title"],
                         font=ctk.CTkFont(size=11), text_color=C["text"],
                         anchor="w",
                         ).grid(row=0, column=2, sticky="w")

            ctk.CTkLabel(row, text=f["severity"],
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=color,
                         ).grid(row=0, column=3, padx=8)

            for w in row.winfo_children():
                w.bind("<Button-1>", lambda e, ff=f: self.on_select(ff))
            row.bind("<Button-1>", lambda e, ff=f: self.on_select(ff))