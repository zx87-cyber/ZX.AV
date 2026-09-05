"""
ZX.AV — Secured by ZX.AI
A lightweight file/URL scanner powered by the VirusTotal public API.

This tool does NOT contain its own malware-detection engine. It works by
submitting file hashes / URLs to VirusTotal, which aggregates results from
70+ real antivirus engines, and displays those real results back to you.
You need your own free VirusTotal API key: https://www.virustotal.com/gui/join-us

License keys are validated locally against license_keys.json (bundled
alongside this app) to unlock the app and to show which tier is active.
This is a local license check for your own product — it does not phone
home or validate against a remote server.
"""

import base64
import hashlib
import json
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib import request as urlrequest
from urllib import error as urlerror

APP_NAME = "ZX.AV"
APP_TAGLINE = "SECURED BY ZX.AI"
APP_VERSION = "1.3.0"

# ---- Tier durations (seconds) — None means never expires ----
TIER_DURATIONS = {
    "TRIAL": 10 * 60,
    "MONTHLY": 30 * 24 * 3600,
    "PRO": 365 * 24 * 3600,
    "LIFETIME": None,
}
TIER_LABELS = {
    "TRIAL": "Trial",
    "MONTHLY": "Member",
    "PRO": "Member Plus",
    "LIFETIME": "Lifetime",
}
TIER_DESCRIPTIONS = {
    "TRIAL": "10 minutes, single use",
    "MONTHLY": "1 month",
    "PRO": "1 year",
    "LIFETIME": "Never expires",
}

# ---- Theme (matches the ZX.AV logo) ----
BG = "#0B0B0C"
PANEL = "#151517"
FG = "#F2F2F2"
MUTED = "#8A8A8E"
LINE = "#5C5C60"
ACCENT = "#4FD1C5"
DANGER = "#E5484D"
OK = "#3DD68C"

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zxav")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

VT_BASE = "https://www.virustotal.com/api/v3"


def resource_path(relative_path):
    """Resolve a bundled resource path, working both from source and from
    a PyInstaller-frozen exe."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def load_license_keys():
    path = resource_path("license_keys.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def load_changelog():
    path = resource_path("CHANGELOG.md")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "Changelog not available."


def validate_license(key):
    """Check a key against the bundled license_keys.json. Returns the
    tier name (str) if valid, else None."""
    key = key.strip().upper()
    keys = load_license_keys()
    for tier, key_list in keys.items():
        if key in key_list:
            return tier
    return None


def compute_expiry(tier, activated_at):
    """Returns the epoch expiry time for a tier/activation, or None if
    the tier never expires."""
    duration = TIER_DURATIONS.get(tier)
    if duration is None:
        return None
    return activated_at + duration


def license_is_expired(cfg):
    tier = cfg.get("license_tier")
    activated_at = cfg.get("activated_at")
    if not tier or not activated_at:
        return True
    expiry = compute_expiry(tier, activated_at)
    if expiry is None:
        return False
    return time.time() >= expiry


def format_expiry(tier, activated_at):
    expiry = compute_expiry(tier, activated_at)
    if expiry is None:
        return "No expiry"
    remaining = expiry - time.time()
    if remaining <= 0:
        return "Expired"
    if tier == "TRIAL":
        mins, secs = divmod(int(remaining), 60)
        return f"Expires in {mins:02d}:{secs:02d}"
    return f"Expires {time.strftime('%Y-%m-%d', time.localtime(expiry))}"


def vt_headers(api_key):
    return {"x-apikey": api_key}


def vt_request(url, api_key, method="GET", data=None):
    req = urlrequest.Request(url, method=method, headers=vt_headers(api_key), data=data)
    with urlrequest.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def sha256_of_file(path, chunk_size=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def vt_lookup_file_hash(file_hash, api_key):
    """Look up an existing report for a file hash. Raises urlerror.HTTPError
    with code 404 if VT has never seen this file."""
    url = f"{VT_BASE}/files/{file_hash}"
    return vt_request(url, api_key)


def vt_upload_file(path, api_key):
    """Upload a file to VirusTotal for scanning (used when VT has no
    existing report for the hash). Returns an analysis id."""
    boundary = "----ZXAVBoundary"
    filename = os.path.basename(path)
    with open(path, "rb") as f:
        file_bytes = f.read()

    body = bytearray()
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += file_bytes
    body += f"\r\n--{boundary}--\r\n".encode()

    req = urlrequest.Request(
        f"{VT_BASE}/files",
        method="POST",
        data=bytes(body),
        headers={
            "x-apikey": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    with urlrequest.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["data"]["id"]


def vt_get_analysis(analysis_id, api_key):
    url = f"{VT_BASE}/analyses/{analysis_id}"
    return vt_request(url, api_key)


def vt_submit_url(target_url, api_key):
    body = f"url={target_url}".encode()
    req = urlrequest.Request(
        f"{VT_BASE}/urls",
        method="POST",
        data=body,
        headers={
            "x-apikey": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urlrequest.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["data"]["id"]


class ZXAVApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — {APP_TAGLINE}")
        self.geometry("760x560")
        self.minsize(680, 480)
        self.configure(bg=BG)

        self.cfg = load_config()
        self.scan_history = []

        self._build_style()

        self._route_startup()

    def _route_startup(self):
        if license_is_expired(self.cfg):
            expired_before = bool(self.cfg.get("license_tier"))
            # Clear the expired license but keep used_keys so a burned
            # TRIAL key can't be reactivated on this install.
            self.cfg.pop("license_tier", None)
            self.cfg.pop("license_key", None)
            self.cfg.pop("activated_at", None)
            save_config(self.cfg)
            self._show_license_gate(
                expired_message="Your previous license expired. Enter a new key to continue."
                if expired_before else None
            )
        elif not self.cfg.get("vt_api_key"):
            self._show_api_key_gate()
        else:
            self._build_main_ui()

    # ---------------- Styling ----------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("PanelLabel.TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI", 20, "bold"))
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#0B0B0C",
            font=("Segoe UI", 10, "bold"),
            padding=8,
        )
        style.map("Accent.TButton", background=[("active", "#3fb9ae")])
        style.configure(
            "Secondary.TButton",
            background=PANEL,
            foreground=FG,
            font=("Segoe UI", 10),
            padding=8,
        )
        style.map("Secondary.TButton", background=[("active", "#1f1f22")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=FG,
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#1c1c1f",
            foreground=MUTED,
            font=("Segoe UI", 9, "bold"),
        )

    def _logo_header(self, parent):
        header = ttk.Frame(parent, style="TFrame")
        header.pack(fill="x", pady=(24, 10))
        ttk.Label(header, text="ZX.AV", style="Title.TLabel").pack()
        ttk.Label(header, text=APP_TAGLINE, style="Muted.TLabel").pack()
        return header

    # ---------------- License gate ----------------
    def _show_license_gate(self, expired_message=None):
        for w in self.winfo_children():
            w.destroy()

        wrap = ttk.Frame(self, style="TFrame")
        wrap.pack(expand=True, fill="both")
        self._logo_header(wrap)

        card = ttk.Frame(wrap, style="Panel.TFrame", padding=24)
        card.pack(pady=20, padx=60, fill="x")

        if expired_message:
            ttk.Label(card, text=expired_message, style="PanelLabel.TLabel",
                      foreground=DANGER, wraplength=420, justify="left").pack(
                anchor="w", pady=(0, 12)
            )

        ttk.Label(card, text="Enter your license key", style="PanelLabel.TLabel",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(card, text="Format: ZXAV-XXXXX-XXXXX-XXXXX-XXXXX", style="Muted.TLabel").pack(
            anchor="w", pady=(2, 12)
        )

        key_var = tk.StringVar()
        entry = ttk.Entry(card, textvariable=key_var, font=("Consolas", 11), width=40)
        entry.pack(fill="x", pady=(0, 12))
        entry.focus()

        status_lbl = ttk.Label(card, text="", style="Muted.TLabel", wraplength=420, justify="left")
        status_lbl.pack(anchor="w", pady=(0, 8))

        def do_activate():
            key_norm = key_var.get().strip().upper()
            tier = validate_license(key_norm)
            used_keys = self.cfg.get("used_keys", [])
            if not tier:
                status_lbl.configure(text="✗ Key not recognized. Check and try again.", foreground=DANGER)
                return
            if key_norm in used_keys:
                status_lbl.configure(
                    text="✗ This key has already been activated on this device.",
                    foreground=DANGER,
                )
                return
            self.cfg["license_tier"] = tier
            self.cfg["license_key"] = key_norm
            self.cfg["activated_at"] = time.time()
            used_keys.append(key_norm)
            self.cfg["used_keys"] = used_keys
            save_config(self.cfg)
            self._route_startup()

        entry.bind("<Return>", lambda e: do_activate())
        ttk.Button(card, text="Activate", style="Accent.TButton", command=do_activate).pack(
            anchor="e"
        )

        tiers_card = ttk.Frame(wrap, style="Panel.TFrame", padding=(16, 12))
        tiers_card.pack(pady=(0, 20), padx=60, fill="x")
        ttk.Label(tiers_card, text="Plans", style="PanelLabel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
        for tier_key in ("TRIAL", "MONTHLY", "PRO", "LIFETIME"):
            row = ttk.Frame(tiers_card, style="Panel.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=TIER_LABELS[tier_key], style="PanelLabel.TLabel",
                      font=("Segoe UI", 9, "bold")).pack(side="left")
            ttk.Label(row, text=TIER_DESCRIPTIONS[tier_key], style="Muted.TLabel").pack(side="right")

    # ---------------- API key gate ----------------
    def _show_api_key_gate(self):
        for w in self.winfo_children():
            w.destroy()

        wrap = ttk.Frame(self, style="TFrame")
        wrap.pack(expand=True, fill="both")
        self._logo_header(wrap)

        tier = self.cfg.get("license_tier", "")
        if tier:
            ttk.Label(wrap, text=f"Plan: {TIER_LABELS.get(tier, tier)}", style="Muted.TLabel").pack()

        card = ttk.Frame(wrap, style="Panel.TFrame", padding=24)
        card.pack(pady=24, padx=60, fill="x")

        ttk.Label(card, text="Connect your VirusTotal API key", style="PanelLabel.TLabel",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            card,
            text=(
                "ZX.AV checks files and URLs against VirusTotal's 70+ real AV\n"
                "engines. Get a free key at virustotal.com \u2192 Settings \u2192 API Key,\n"
                "then paste it below. It's stored only on this machine."
            ),
            style="Muted.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(2, 12))

        key_var = tk.StringVar(value=self.cfg.get("vt_api_key", ""))
        entry = ttk.Entry(card, textvariable=key_var, font=("Consolas", 10), width=48, show="*")
        entry.pack(fill="x", pady=(0, 8))
        entry.focus()

        show_var = tk.BooleanVar(value=False)

        def toggle_show():
            entry.configure(show="" if show_var.get() else "*")

        ttk.Checkbutton(card, text="Show key", variable=show_var, command=toggle_show).pack(
            anchor="w", pady=(0, 12)
        )

        status_lbl = ttk.Label(card, text="", style="Muted.TLabel")
        status_lbl.pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(card, style="Panel.TFrame")
        btn_row.pack(fill="x")

        verify_btn = ttk.Button(btn_row, text="Verify key", style="Secondary.TButton")
        verify_btn.pack(side="left")
        continue_btn = ttk.Button(btn_row, text="Save & continue", style="Accent.TButton")
        continue_btn.pack(side="right")
        skip_btn = ttk.Button(btn_row, text="Skip for now", style="Secondary.TButton")
        skip_btn.pack(side="right", padx=(0, 10))

        def set_status(text, ok=None):
            color = OK if ok is True else DANGER if ok is False else MUTED
            self.after(0, lambda: status_lbl.configure(text=text, foreground=color))

        def do_verify():
            key = key_var.get().strip()
            if not key:
                set_status("Enter a key first.", ok=False)
                return
            verify_btn.configure(state="disabled")
            set_status("Checking with VirusTotal...")

            def worker():
                try:
                    vt_request(f"{VT_BASE}/users/{key}", key)
                    set_status("✓ Key verified — connected to VirusTotal.", ok=True)
                except urlerror.HTTPError as e:
                    if e.code in (401, 403):
                        set_status("✗ Invalid API key.", ok=False)
                    else:
                        set_status(f"✗ VirusTotal error ({e.code}).", ok=False)
                except Exception as e:
                    set_status(f"✗ Couldn't reach VirusTotal: {e}", ok=False)
                finally:
                    self.after(0, lambda: verify_btn.configure(state="normal"))

            threading.Thread(target=worker, daemon=True).start()

        def do_continue():
            key = key_var.get().strip()
            if not key:
                set_status("Enter a key, or choose Skip for now.", ok=False)
                return
            self.cfg["vt_api_key"] = key
            save_config(self.cfg)
            self._build_main_ui()

        def do_skip():
            self._build_main_ui()

        verify_btn.configure(command=do_verify)
        continue_btn.configure(command=do_continue)
        skip_btn.configure(command=do_skip)
        entry.bind("<Return>", lambda e: do_continue())

    # ---------------- Menu bar ----------------
    def _build_menu_bar(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Settings...", command=self._open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Scan a file...", command=self._scan_file_dialog)
        scan_menu.add_command(label="Scan a URL...", command=self._scan_url_dialog)
        menubar.add_cascade(label="Scan", menu=scan_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh dashboard", command=self._build_main_ui)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="What's new (changelog)", command=self._show_changelog)
        help_menu.add_command(label="About ZX.AV", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.configure(menu=menubar)

    def _show_changelog(self):
        win = tk.Toplevel(self)
        win.title("What's new — ZX.AV")
        win.configure(bg=BG)
        win.geometry("480x420")
        text = tk.Text(win, bg=PANEL, fg=FG, font=("Consolas", 10), wrap="word",
                        borderwidth=0, highlightthickness=0, padx=16, pady=16)
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("1.0", load_changelog())
        text.configure(state="disabled")

    def _show_about(self):
        tier = self.cfg.get("license_tier", "UNKNOWN")
        messagebox.showinfo(
            "About ZX.AV",
            f"ZX.AV — {APP_TAGLINE}\nVersion {APP_VERSION}\n\n"
            "Scans files and URLs using the VirusTotal API (70+ real AV engines).\n"
            f"Plan: {TIER_LABELS.get(tier, tier)}",
        )

    # ---------------- Main dashboard ----------------
    def _build_main_ui(self):
        for w in self.winfo_children():
            w.destroy()

        self._build_menu_bar()

        top = ttk.Frame(self, style="TFrame", padding=(20, 16))
        top.pack(fill="x")
        left = ttk.Frame(top, style="TFrame")
        left.pack(side="left")
        ttk.Label(left, text="ZX.AV", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text=f"{APP_TAGLINE}  ·  v{APP_VERSION}", style="Muted.TLabel").pack(anchor="w")

        right = ttk.Frame(top, style="TFrame")
        right.pack(side="right")
        tier = self.cfg.get("license_tier", "UNKNOWN")
        tier_label = TIER_LABELS.get(tier, tier)
        self.plan_var = tk.StringVar(value=f"Plan: {tier_label}")
        self.expiry_var = tk.StringVar(value=format_expiry(tier, self.cfg.get("activated_at", 0)))
        ttk.Label(right, textvariable=self.plan_var, style="Muted.TLabel").pack(anchor="e")
        ttk.Label(right, textvariable=self.expiry_var, style="Muted.TLabel").pack(anchor="e")
        api_status = "API key set" if self.cfg.get("vt_api_key") else "No API key set"
        ttk.Label(right, text=api_status, style="Muted.TLabel").pack(anchor="e")
        ttk.Button(right, text="Settings", style="Secondary.TButton",
                   command=self._open_settings).pack(anchor="e", pady=(6, 0))

        sep = tk.Frame(self, bg=LINE, height=1)
        sep.pack(fill="x", padx=20)

        body = ttk.Frame(self, style="TFrame", padding=20)
        body.pack(fill="both", expand=True)

        actions = ttk.Frame(body, style="Panel.TFrame", padding=16)
        actions.pack(fill="x", pady=(0, 16))
        ttk.Label(actions, text="Run a scan", style="PanelLabel.TLabel",
                  font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Button(actions, text="Scan a file", style="Accent.TButton",
                   command=self._scan_file_dialog).grid(row=1, column=0, padx=(0, 10))
        ttk.Button(actions, text="Scan a URL", style="Secondary.TButton",
                   command=self._scan_url_dialog).grid(row=1, column=1, padx=(0, 10))
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=200)
        self.progress.grid(row=1, column=2, padx=(10, 0))

        stats_row = ttk.Frame(body, style="TFrame")
        stats_row.pack(fill="x", pady=(0, 16))
        self.stat_cards = {}
        for i, (key, label) in enumerate([
            ("total", "Total scans"),
            ("clean", "Clean"),
            ("flagged", "Flagged"),
            ("last", "Last scan"),
        ]):
            card = ttk.Frame(stats_row, style="Panel.TFrame", padding=14)
            card.grid(row=0, column=i, sticky="nsew", padx=(0, 10) if i < 3 else 0)
            stats_row.columnconfigure(i, weight=1)
            ttk.Label(card, text=label, style="Muted.TLabel").pack(anchor="w")
            val_lbl = ttk.Label(card, text="0", style="PanelLabel.TLabel", font=("Segoe UI", 18, "bold"))
            val_lbl.pack(anchor="w", pady=(4, 0))
            self.stat_cards[key] = val_lbl

        ttk.Label(body, text="Overview", style="TLabel", font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(4, 6)
        )

        diagrams_row = ttk.Frame(body, style="TFrame")
        diagrams_row.pack(fill="x", pady=(0, 16))

        ring_card = ttk.Frame(diagrams_row, style="Panel.TFrame", padding=14)
        ring_card.pack(side="left", padx=(0, 10))
        ttk.Label(ring_card, text="Protection", style="PanelLabel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self.ring_canvas = tk.Canvas(ring_card, width=140, height=140, bg=PANEL,
                                      highlightthickness=0)
        self.ring_canvas.pack()

        bars_card = ttk.Frame(diagrams_row, style="Panel.TFrame", padding=14)
        bars_card.pack(side="left", fill="both", expand=True)
        ttk.Label(bars_card, text="Detections (recent scans)", style="PanelLabel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self.bars_canvas = tk.Canvas(bars_card, width=380, height=140, bg=PANEL,
                                      highlightthickness=0)
        self.bars_canvas.pack(fill="both", expand=True)

        ttk.Label(body, text="Scan history", style="TLabel", font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(4, 6)
        )

        columns = ("target", "type", "result", "detections", "time")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=10)
        for col, label, width in [
            ("target", "Target", 260),
            ("type", "Type", 60),
            ("result", "Result", 100),
            ("detections", "Detections", 100),
            ("time", "Scanned", 140),
        ]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.tag_configure("clean", foreground=OK)
        self.tree.tag_configure("flagged", foreground=DANGER)

        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status_var, style="Muted.TLabel",
                                padding=(20, 6))
        status_bar.pack(fill="x", side="bottom")

        self._refresh_stats()
        self._start_license_watchdog()

    def _start_license_watchdog(self):
        """Keeps the plan/expiry label live and boots back to the license
        gate the moment the current key expires (matters most for the
        10-minute TRIAL tier, which can expire mid-session)."""
        tier = self.cfg.get("license_tier")
        activated_at = self.cfg.get("activated_at", 0)

        def tick():
            if license_is_expired(self.cfg):
                self._route_startup()
                return
            self.expiry_var.set(format_expiry(tier, activated_at))
            self.after(1000, tick)

        tick()

    def _refresh_stats(self):
        total = len(self.scan_history)
        clean = sum(1 for e in self.scan_history if e["result"] == "CLEAN")
        flagged = sum(1 for e in self.scan_history if e["result"] == "FLAGGED")
        last = self.scan_history[-1]["time"] if self.scan_history else "—"
        self.stat_cards["total"].configure(text=str(total))
        self.stat_cards["clean"].configure(text=str(clean))
        self.stat_cards["flagged"].configure(text=str(flagged))
        self.stat_cards["last"].configure(text=last)
        self._draw_protection_ring(clean, flagged)
        self._draw_detection_bars()

    def _draw_protection_ring(self, clean, flagged):
        c = self.ring_canvas
        c.delete("all")
        total = clean + flagged
        pct_clean = (clean / total) if total else 1.0
        cx, cy, r = 70, 70, 50
        bbox = (cx - r, cy - r, cx + r, cy + r)
        if total == 0:
            c.create_oval(*bbox, outline=MUTED, width=10)
        else:
            clean_extent = 360 * pct_clean
            c.create_arc(*bbox, start=90, extent=-clean_extent, style="arc",
                         outline=OK, width=10)
            c.create_arc(*bbox, start=90 - clean_extent, extent=-(360 - clean_extent),
                         style="arc", outline=DANGER, width=10)
        pct_text = f"{round(pct_clean * 100)}%" if total else "—"
        c.create_text(cx, cy - 6, text=pct_text, fill=FG, font=("Segoe UI", 16, "bold"))
        c.create_text(cx, cy + 14, text="clean", fill=MUTED, font=("Segoe UI", 8))

    def _draw_detection_bars(self):
        c = self.bars_canvas
        c.delete("all")
        recent = list(reversed(self.scan_history[-6:]))
        if not recent:
            c.create_text(190, 70, text="No scans yet", fill=MUTED, font=("Segoe UI", 9))
            return
        max_det = max((e["detections"] for e in recent), default=1) or 1
        row_h = 20
        bar_max_w = 220
        label_w = 110
        for i, entry in enumerate(recent):
            y = 12 + i * row_h
            name = entry["target"]
            short = name if len(name) <= 16 else name[:14] + "…"
            c.create_text(4, y, text=short, fill=MUTED, font=("Segoe UI", 8), anchor="w")
            bar_w = int((entry["detections"] / max_det) * bar_max_w) if entry["detections"] else 2
            color = DANGER if entry["detections"] > 0 else OK
            c.create_rectangle(label_w, y - 6, label_w + bar_w, y + 6, fill=color, outline="")
            c.create_text(label_w + bar_w + 8, y, text=str(entry["detections"]), fill=FG,
                          font=("Segoe UI", 8), anchor="w")

    def _open_settings(self):
        # Reuses the startup API key screen (with live Verify) so changing
        # the key later goes through the same tested flow as first setup.
        self._show_api_key_gate()

    def _require_api_key(self):
        key = self.cfg.get("vt_api_key")
        if not key:
            messagebox.showwarning(
                "API key required",
                "Add your VirusTotal API key in Settings before scanning.",
            )
            self._open_settings()
            return None
        return key

    # ---------------- File scan ----------------
    def _scan_file_dialog(self):
        api_key = self._require_api_key()
        if not api_key:
            return
        path = filedialog.askopenfilename(title="Choose a file to scan")
        if not path:
            return
        self._run_async(self._scan_file, path, api_key)

    def _scan_file(self, path, api_key):
        self._set_status(f"Hashing {os.path.basename(path)}...")
        file_hash = sha256_of_file(path)

        try:
            self._set_status("Checking VirusTotal for an existing report...")
            report = vt_lookup_file_hash(file_hash, api_key)
            stats = report["data"]["attributes"]["last_analysis_stats"]
        except urlerror.HTTPError as e:
            if e.code == 404:
                self._set_status("No existing report — uploading file for a fresh scan...")
                analysis_id = vt_upload_file(path, api_key)
                stats = self._poll_analysis(analysis_id, api_key)
            else:
                self._scan_error(f"VirusTotal error ({e.code}): {e.reason}")
                return
        except Exception as e:
            self._scan_error(f"Scan failed: {e}")
            return

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_flags = malicious + suspicious
        result = "FLAGGED" if total_flags > 0 else "CLEAN"
        self._record_result(os.path.basename(path), "File", result, total_flags)
        self._set_status(f"Done — {os.path.basename(path)}: {result} ({total_flags} detections).")

    # ---------------- URL scan ----------------
    def _scan_url_dialog(self):
        api_key = self._require_api_key()
        if not api_key:
            return
        target = simpledialog.askstring("Scan a URL", "Enter the URL to check:", parent=self)
        if not target:
            return
        self._run_async(self._scan_url, target.strip(), api_key)

    def _scan_url(self, target, api_key):
        try:
            self._set_status(f"Submitting {target} to VirusTotal...")
            analysis_id = vt_submit_url(target, api_key)
            stats = self._poll_analysis(analysis_id, api_key)
        except Exception as e:
            self._scan_error(f"Scan failed: {e}")
            return

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_flags = malicious + suspicious
        result = "FLAGGED" if total_flags > 0 else "CLEAN"
        self._record_result(target, "URL", result, total_flags)
        self._set_status(f"Done — {target}: {result} ({total_flags} detections).")

    # ---------------- Shared helpers ----------------
    def _poll_analysis(self, analysis_id, api_key, timeout=90, interval=3):
        elapsed = 0
        while elapsed < timeout:
            data = vt_get_analysis(analysis_id, api_key)
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                return data["data"]["attributes"]["stats"]
            self._set_status(f"Analysis in progress ({status})...")
            time.sleep(interval)
            elapsed += interval
        raise TimeoutError("VirusTotal analysis did not complete in time.")

    def _record_result(self, target, kind, result, detections):
        entry = {
            "target": target,
            "type": kind,
            "result": result,
            "detections": detections,
            "time": time.strftime("%Y-%m-%d %H:%M"),
        }
        self.scan_history.append(entry)
        tag = "flagged" if result == "FLAGGED" else "clean"
        self.after(0, lambda: self.tree.insert(
            "", 0,
            values=(entry["target"], entry["type"], entry["result"], entry["detections"], entry["time"]),
            tags=(tag,),
        ))
        self.after(0, self._refresh_stats)

    def _scan_error(self, message):
        self._set_status(message)
        self.after(0, lambda: messagebox.showerror("Scan error", message))

    def _set_status(self, text):
        self.after(0, lambda: self.status_var.set(text))

    def _run_async(self, fn, *args):
        self.progress.start(12)

        def wrapper():
            try:
                fn(*args)
            finally:
                self.after(0, self.progress.stop)

        threading.Thread(target=wrapper, daemon=True).start()


if __name__ == "__main__":
    app = ZXAVApp()
    app.mainloop()
