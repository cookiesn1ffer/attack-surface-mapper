#!/usr/bin/env python3
"""
Attack Surface Mapper - Desktop GUI
Run with: python app.py
"""

from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Check deps before anything else
MISSING_DEPS = []
for _pkg, _mod in [("requests","requests"),("dnspython","dns"),
                   ("rich","rich"),("urllib3","urllib3")]:
    try:
        __import__(_mod)
    except ImportError:
        MISSING_DEPS.append(_pkg)

BG     = "#0f1117"
CARD   = "#161926"
BORDER = "#252836"
ACCENT = "#00d4ff"
GREEN  = "#00e676"
YELLOW = "#ffd740"
RED    = "#ff5252"
DIM    = "#6b7280"
TEXT   = "#e0e0e0"
LOG_BG = "#090b10"
BTN_HV = "#00b8e0"


def _tag_for(line):
    if any(k in line for k in ("HTTP 200","Found","Subdomains","unique")):
        return "green"
    if any(k in line for k in ("Phase","Report","Attack Surface","Mapper")):
        return "accent"
    if any(k in line for k in ("Warning","warning","HTTP 30","Limiting")):
        return "yellow"
    if any(k in line.lower() for k in ("error","http 4","http 5")):
        return "red"
    if any(k in line for k in ("---","===","crt.sh","brute")):
        return "dim"
    return "normal"


class HoverButton(tk.Button):
    def __init__(self, master, hover_bg=None, hover_fg=None, **kw):
        self._nbg = kw.get("bg","white")
        self._nfg = kw.get("fg","black")
        self._hbg = hover_bg or self._nbg
        self._hfg = hover_fg or self._nfg
        super().__init__(master, **kw)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)

    def _enter(self, _):
        if str(self.cget("state")) != "disabled":
            self.configure(bg=self._hbg, fg=self._hfg)

    def _leave(self, _):
        self.configure(bg=self._nbg, fg=self._nfg)


class MapperApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # DPI awareness AFTER super().__init__() — prevents ghost window on Windows
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

        self.title("Attack Surface Mapper")
        self.geometry("1140x720")
        self.minsize(900, 580)
        self.configure(bg=BG)
        self.option_add("*tearOff", False)

        if MISSING_DEPS:
            self.withdraw()
            fix = "python -m pip install " + " ".join(MISSING_DEPS)
            messagebox.showerror(
                "Missing Dependencies",
                "These packages are not installed:\n\n"
                + "  " + ", ".join(MISSING_DEPS) + "\n\n"
                + "Run this in your terminal, then restart:\n\n"
                + "  " + fix
            )
            self.destroy()
            return

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Vertical.TScrollbar",
                        background=BORDER, troughcolor=LOG_BG,
                        bordercolor=LOG_BG, arrowcolor=DIM, relief="flat")
        style.map("Vertical.TScrollbar", background=[("active","#3a3d4a")])

        self._proc = None
        self._q = queue.Queue()
        self._report_path = None

        self._build()
        self._poll()

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._sidebar()
        self._main_panel()

    def _sidebar(self):
        sb = tk.Frame(self, bg=CARD, width=280)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)

        r = 0

        tk.Label(sb, text="Attack Surface Mapper",
                 font=("Segoe UI",12,"bold"), bg=CARD, fg=ACCENT,
                 anchor="w").grid(row=r, column=0, padx=18, pady=(20,0), sticky="w")
        r += 1
        tk.Label(sb, text="Subdomain + Attack Surface Scanner",
                 font=("Segoe UI",8), bg=CARD, fg=DIM,
                 anchor="w").grid(row=r, column=0, padx=18, pady=(0,4), sticky="w")
        r += 1

        _div(sb, r); r += 1

        _lbl(sb, r, "TARGET DOMAIN"); r += 1
        self._domain_var = tk.StringVar()
        self._domain_entry = _ent(sb, r, self._domain_var); r += 1
        _placeholder(self._domain_entry, self._domain_var, "example.com")

        _gap(sb, r); r += 1

        _lbl(sb, r, "WORDLIST"); r += 1
        wf = tk.Frame(sb, bg=CARD)
        wf.grid(row=r, column=0, padx=16, pady=(0,4), sticky="ew")
        wf.grid_columnconfigure(0, weight=1)
        self._wl_var = tk.StringVar(value="built-in")
        tk.Entry(wf, textvariable=self._wl_var, bg="#0d0f18", fg=DIM,
                 insertbackground=TEXT, relief="flat", font=("Segoe UI",10),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).grid(row=0, column=0, sticky="ew", ipady=5)
        HoverButton(wf, text="Browse", bg=BORDER, fg=TEXT,
                    hover_bg="#2a2d3a", hover_fg=TEXT,
                    activebackground="#2a2d3a", activeforeground=TEXT,
                    relief="flat", font=("Segoe UI",9),
                    cursor="hand2", command=self._pick_wl, padx=8
                    ).grid(row=0, column=1, padx=(6,0), sticky="ns")
        r += 1

        _div(sb, r); r += 1

        _lbl(sb, r, "OPTIONS"); r += 1
        self._brute_var = tk.BooleanVar(value=True)
        self._ports_var = tk.BooleanVar(value=True)
        self._fp_var    = tk.BooleanVar(value=True)
        for label, var in [("DNS Brute Force",    self._brute_var),
                           ("Port Scan (0-65535)", self._ports_var),
                           ("Tech Fingerprinting", self._fp_var)]:
            _chk(sb, r, label, var); r += 1

        _div(sb, r); r += 1

        _lbl(sb, r, "ADVANCED"); r += 1
        adv = tk.Frame(sb, bg=CARD)
        adv.grid(row=r, column=0, padx=16, pady=(0,8), sticky="ew")
        adv.grid_columnconfigure((0,1), weight=1)
        self._range_var   = tk.StringVar(value="1-65535")
        self._workers_var = tk.StringVar(value="50")
        self._limit_var   = tk.StringVar(value="0")
        _afld(adv, 0, 0, "Port range",  self._range_var)
        _afld(adv, 0, 1, "DNS workers", self._workers_var)
        lf = tk.Frame(adv, bg=CARD)
        lf.grid(row=1, column=0, columnspan=2, pady=(8,0), sticky="ew")
        lf.grid_columnconfigure(0, weight=1)
        tk.Label(lf, text="Subdomain limit (0 = all)", font=("Segoe UI",9),
                 bg=CARD, fg=DIM).grid(row=0, column=0, sticky="w")
        tk.Entry(lf, textvariable=self._limit_var, bg="#0d0f18", fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=("Segoe UI",10),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).grid(row=1, column=0, sticky="ew", ipady=5)
        r += 1

        filler = tk.Frame(sb, bg=CARD)
        filler.grid(row=r, column=0, sticky="nsew")
        sb.grid_rowconfigure(r, weight=1)
        r += 1

        self._start_btn = HoverButton(
            sb, text="  Start Scan",
            bg=ACCENT, fg=BG, hover_bg=BTN_HV, hover_fg=BG,
            activebackground=BTN_HV, activeforeground=BG,
            font=("Segoe UI",13,"bold"), relief="flat",
            cursor="hand2", command=self._toggle)
        self._start_btn.grid(row=r, column=0, padx=16, pady=(0,18),
                             sticky="ew", ipady=11)

    def _main_panel(self):
        main = tk.Frame(self, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        bar = tk.Frame(main, bg=CARD, height=52)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(0, weight=1)
        bar.grid_rowconfigure(0, weight=1)

        self._status = tk.Label(bar, text="Ready  -  enter a domain and hit Start",
                                font=("Segoe UI",11), bg=CARD, fg=DIM, anchor="w")
        self._status.grid(row=0, column=0, padx=16, sticky="w")

        self._open_btn = HoverButton(
            bar, text="Open Report",
            bg=BORDER, fg=DIM, hover_bg="#2a2d3a", hover_fg=TEXT,
            activebackground="#2a2d3a", activeforeground=TEXT,
            font=("Segoe UI",10), relief="flat", cursor="hand2",
            state="disabled", command=self._open_report)
        self._open_btn.grid(row=0, column=1, padx=14, sticky="e", ipady=6, ipadx=12)

        tk.Frame(main, bg=BORDER, height=1).grid(row=1, column=0, sticky="ew")

        lf = tk.Frame(main, bg=LOG_BG)
        lf.grid(row=2, column=0, sticky="nsew")
        lf.grid_rowconfigure(0, weight=1)
        lf.grid_columnconfigure(0, weight=1)

        self._log = tk.Text(lf, bg=LOG_BG, fg=TEXT, font=("Consolas",11),
                            relief="flat", wrap="word", padx=16, pady=14,
                            state="disabled", cursor="arrow",
                            selectbackground="#252836", spacing1=2, spacing3=2)
        self._log.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(lf, orient="vertical", command=self._log.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self._log.configure(yscrollcommand=vsb.set)

        self._log.tag_configure("accent", foreground=ACCENT)
        self._log.tag_configure("green",  foreground=GREEN)
        self._log.tag_configure("yellow", foreground=YELLOW)
        self._log.tag_configure("red",    foreground=RED)
        self._log.tag_configure("dim",    foreground=DIM)
        self._log.tag_configure("normal", foreground=TEXT)

    def _pick_wl(self):
        path = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[("Text files","*.txt"),("All files","*.*")])
        if path:
            self._wl_var.set(path)

    def _toggle(self):
        if self._proc and self._proc.poll() is None:
            self._stop()
        else:
            self._start()

    def _start(self):
        domain = self._domain_var.get().strip()
        if not domain or getattr(self._domain_entry, "_ph_active", False):
            # Flash the domain field border red to prompt the user
            self._domain_entry.configure(highlightbackground=RED, highlightcolor=RED)
            self.after(1200, lambda: self._domain_entry.configure(
                highlightbackground=BORDER, highlightcolor=ACCENT))
            self._domain_entry.focus_set()
            self._status.configure(text="Enter a target domain first.", fg=YELLOW)
            return

        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.configure(state="disabled")
        self._report_path = None
        self._open_btn.configure(state="disabled", fg=DIM)
        self._open_btn._nfg = DIM

        cmd = [sys.executable, str(Path(__file__).parent / "mapper.py"), domain]
        wl = self._wl_var.get().strip()
        if wl and wl != "built-in" and Path(wl).is_file():
            cmd += ["--wordlist", wl]
        if not self._brute_var.get():   cmd.append("--no-brute")
        if not self._ports_var.get():   cmd.append("--no-ports")
        if not self._fp_var.get():      cmd.append("--no-fingerprint")
        rng = self._range_var.get().strip()
        if rng and rng != "1-65535":    cmd += ["--ports", rng]
        w = self._workers_var.get().strip()
        if w and w != "50":             cmd += ["--workers", w]
        lim = self._limit_var.get().strip()
        if lim and lim != "0":          cmd += ["--limit", lim]

        report = Path(__file__).parent / (domain + "_report.html")
        cmd += ["--output", str(report)]
        self._report_path = report

        self._start_btn.configure(text="  Stop", bg=RED,
                                  activebackground="#cc3333", fg="white")
        self._start_btn._nbg = RED
        self._start_btn._hbg = "#cc3333"
        self._status.configure(text="Scanning " + domain + "...", fg=ACCENT)

        env = os.environ.copy()
        env["NO_COLOR"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["PYTHONUNBUFFERED"] = "1"

        # Insert -u (unbuffered) right after the interpreter
        cmd.insert(1, "-u")

        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT,
                                      text=True, bufsize=1, env=env,
                                      encoding="utf-8", errors="replace")
        threading.Thread(target=self._read, daemon=True).start()

    def _stop(self):
        if self._proc:
            try:
                # Kill the whole process tree so nmap subprocess also dies
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self._proc.pid)],
                    capture_output=True
                )
            except Exception:
                self._proc.terminate()
        self._reset_btn()
        self._status.configure(text="Stopped.", fg=YELLOW)

    def _reset_btn(self):
        self._start_btn.configure(text="  Start Scan", bg=ACCENT,
                                  activebackground=BTN_HV, fg=BG)
        self._start_btn._nbg = ACCENT
        self._start_btn._hbg = BTN_HV

    def _read(self):
        for line in self._proc.stdout:
            self._q.put(line)
        self._proc.wait()
        self._q.put(None)

    def _poll(self):
        try:
            while True:
                item = self._q.get_nowait()
                if item is None:
                    self._reset_btn()
                    if self._report_path and self._report_path.exists():
                        self._status.configure(text="Done  -  Report ready.", fg=GREEN)
                        self._open_btn.configure(state="normal", fg=TEXT)
                        self._open_btn._nfg = TEXT
                        self._open_btn._hfg = TEXT
                    else:
                        self._status.configure(text="Finished.", fg=TEXT)
                else:
                    clean = ANSI_ESCAPE.sub("", item)
                    self._write(clean, _tag_for(clean))
        except queue.Empty:
            pass
        self.after(40, self._poll)

    def _write(self, text, tag="normal"):
        self._log.configure(state="normal")
        self._log.insert("end", text, tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _open_report(self):
        if self._report_path and self._report_path.exists():
            webbrowser.open(self._report_path.as_uri())


def _lbl(p, row, text):
    tk.Label(p, text=text, font=("Segoe UI",8,"bold"),
             bg=CARD, fg=DIM).grid(row=row, column=0, padx=18,
                                   pady=(10,3), sticky="w")

def _ent(p, row, var):
    e = tk.Entry(p, textvariable=var, bg="#0d0f18", fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=("Segoe UI",11),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT)
    e.grid(row=row, column=0, padx=16, pady=(0,4), sticky="ew", ipady=7)
    return e

def _placeholder(entry, var, text):
    entry._ph_active = True
    var.set(text)
    entry.configure(fg=DIM)

    def _in(_):
        if entry._ph_active:
            entry._ph_active = False
            entry.configure(fg=TEXT)
            var.set("")

    def _out(_):
        if not var.get().strip():
            entry._ph_active = True
            entry.configure(fg=DIM)
            var.set(text)

    entry.bind("<FocusIn>",  _in)
    entry.bind("<FocusOut>", _out)

def _chk(p, row, text, var):
    f = tk.Frame(p, bg=CARD)
    f.grid(row=row, column=0, padx=16, pady=3, sticky="w")
    box = tk.Canvas(f, width=16, height=16, bg=CARD, highlightthickness=0)
    box.pack(side="left")
    lbl = tk.Label(f, text="  "+text, font=("Segoe UI",11),
                   bg=CARD, fg=TEXT, cursor="hand2")
    lbl.pack(side="left")

    def _draw():
        box.delete("all")
        if var.get():
            box.create_rectangle(0, 0, 16, 16, fill=ACCENT, outline=ACCENT)
            box.create_line(3, 8, 7, 13, fill=BG, width=2)
            box.create_line(7, 13, 14, 4, fill=BG, width=2)
        else:
            box.create_rectangle(0, 0, 16, 16, fill=CARD, outline=BORDER, width=1)

    def _toggle(_=None):
        var.set(not var.get())
        _draw()

    box.bind("<Button-1>", _toggle)
    lbl.bind("<Button-1>", _toggle)
    _draw()

def _div(p, row):
    tk.Frame(p, height=1, bg=BORDER).grid(row=row, column=0, sticky="ew",
                                           padx=14, pady=8)

def _gap(p, row, h=4):
    tk.Frame(p, height=h, bg=CARD).grid(row=row, column=0)

def _afld(p, row, col, label, var):
    pad = (0,5) if col == 0 else (5,0)
    f = tk.Frame(p, bg=CARD)
    f.grid(row=row, column=col, padx=pad, sticky="ew")
    f.grid_columnconfigure(0, weight=1)
    tk.Label(f, text=label, font=("Segoe UI",9),
             bg=CARD, fg=DIM).grid(row=0, column=0, sticky="w")
    tk.Entry(f, textvariable=var, bg="#0d0f18", fg=TEXT,
             insertbackground=TEXT, relief="flat", font=("Segoe UI",10),
             highlightthickness=1, highlightbackground=BORDER,
             highlightcolor=ACCENT).grid(row=1, column=0, sticky="ew", ipady=5)


if __name__ == "__main__":
    app = MapperApp()
    app.mainloop()
