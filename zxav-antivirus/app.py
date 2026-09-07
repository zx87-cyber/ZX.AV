import csv
import hashlib
import json
import os
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkFont
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlencode


# ========================================================
# ZX.AV
# SECURED BY ZX.AI
# ========================================================

APP_NAME = "ZX.AV"
APP_TAGLINE = "SECURED BY ZX.AI"
APP_VERSION = "2.1.0"

# --------------------------------------------------------
# License tiers
# --------------------------------------------------------

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

# --------------------------------------------------------
# UI colors
# --------------------------------------------------------

BG = "#101112"
SIDEBAR = "#151617"
PANEL = "#191B1D"
PANEL_LIGHT = "#202224"
PANEL_HOVER = "#282A2D"

WHITE = "#F1F1F1"
TEXT = "#D7D7D7"
MUTED = "#8C8F93"
MUTED_DARK = "#65686C"

BORDER = "#2B2D30"
BORDER_LIGHT = "#36383B"

GREEN = "#55B982"
RED = "#D96565"
YELLOW = "#C7A65B"

# --------------------------------------------------------
# Paths
# --------------------------------------------------------

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zxav")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
HISTORY_PATH = os.path.join(CONFIG_DIR, "scan_history.json")

VT_BASE = "https://www.virustotal.com/api/v3"

MAX_HISTORY = 500


# ========================================================
# Resource helpers
# ========================================================

def resource_path(relative_path):
    """
    Return a path that works both when running normally and
    when packaged with PyInstaller.
    """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


# ========================================================
# Font helper
# ========================================================

def get_safe_font(family, size, weight="normal"):
    """
    Return a font tuple that works across Linux, Windows,
    and other Tk platforms.
    """

    fallbacks = [
        family,
        "Segoe UI",
        "Arial",
        "Liberation Sans",
        "DejaVu Sans",
        "Helvetica",
    ]

    for font_name in fallbacks:
        try:
            test_font = tkFont.Font(
                family=font_name,
                size=size,
                weight=weight,
            )

            if test_font.actual("family"):
                test_font.destroy()
                return (font_name, size, weight)

            test_font.destroy()

        except tk.TclError:
            continue

    return ("TkDefaultFont", size, weight)


# Backwards-compatible name matching the splash code.
_get_safe_font = get_safe_font


# ========================================================
# Configuration
# ========================================================

def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)

    if not os.path.exists(CONFIG_PATH):
        return {}

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, dict):
            return data

    except (OSError, json.JSONDecodeError):
        pass

    return {}


def save_config(config):
    os.makedirs(CONFIG_DIR, exist_ok=True)

    temp_path = CONFIG_PATH + ".tmp"

    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(config, file, indent=2)

        os.replace(temp_path, CONFIG_PATH)

    except OSError:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass


def load_license_keys():
    possible_paths = [
        resource_path("license_keys.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "license_keys.json"),
    ]

    for path in possible_paths:
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)

            if isinstance(data, dict):
                return data

        except (OSError, json.JSONDecodeError):
            continue

    return {}


def load_changelog():
    paths = [
        resource_path("CHANGELOG.md"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHANGELOG.md"),
    ]

    for path in paths:
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as file:
                return file.read()

        except OSError:
            continue

    return "No changelog is currently available."


# ========================================================
# Persistent scan history
# ========================================================

def load_scan_history():
    if not os.path.exists(HISTORY_PATH):
        return []

    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data[-MAX_HISTORY:]

    except (OSError, json.JSONDecodeError):
        pass

    return []


def save_scan_history(history):
    os.makedirs(CONFIG_DIR, exist_ok=True)

    history = history[-MAX_HISTORY:]

    temp_path = HISTORY_PATH + ".tmp"

    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(
                history,
                file,
                indent=2,
                ensure_ascii=False,
            )

        os.replace(temp_path, HISTORY_PATH)

    except OSError:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass


# ========================================================
# License helpers
# ========================================================

def validate_license(key, license_keys):
    key = key.strip().upper()

    if not key:
        return None

    tier = license_keys.get(key)

    if tier is None:
        return None

    tier = str(tier).upper()

    if tier not in TIER_DURATIONS:
        return None

    return tier


def compute_expiry(tier, activated_at):
    duration = TIER_DURATIONS.get(tier)

    if duration is None:
        return None

    return activated_at + duration


def license_is_expired(config):
    tier = config.get("license_tier")
    expiry = config.get("license_expiry")

    if not tier:
        return True

    if tier == "LIFETIME":
        return False

    if expiry is None:
        return True

    try:
        return time.time() >= float(expiry)
    except (TypeError, ValueError):
        return True


def format_expiry(config):
    tier = config.get("license_tier")

    if not tier:
        return "No license"

    if tier == "LIFETIME":
        return "Never expires"

    expiry = config.get("license_expiry")

    if expiry is None:
        return "Unknown"

    try:
        remaining = max(0, float(expiry) - time.time())

        if remaining < 60:
            return f"{int(remaining)}s remaining"

        if remaining < 3600:
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            return f"{minutes}m {seconds}s remaining"

        if remaining < 86400:
            hours = int(remaining // 3600)
            minutes = int((remaining % 3600) // 60)
            return f"{hours}h {minutes}m remaining"

        days = int(remaining // 86400)

        try:
            date_text = datetime.fromtimestamp(
                float(expiry)
            ).strftime("%d %b %Y")
        except (ValueError, OSError):
            date_text = "unknown date"

        return f"{days}d remaining • expires {date_text}"

    except (TypeError, ValueError):
        return "Unknown"


# ========================================================
# File helpers
# ========================================================

def format_bytes(size):
    if size is None:
        return "—"

    try:
        size = float(size)
    except (TypeError, ValueError):
        return "—"

    units = ["B", "KB", "MB", "GB", "TB"]

    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"

            return f"{size:.1f} {unit}"

        size /= 1024

    return "—"


def sha256_of_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ========================================================
# VirusTotal helpers
# ========================================================

def vt_headers(api_key):
    return {
        "x-apikey": api_key,
        "Accept": "application/json",
    }


def vt_request(url, api_key, method="GET", data=None, headers=None):
    request_headers = vt_headers(api_key)

    if headers:
        request_headers.update(headers)

    req = urlrequest.Request(
        url,
        data=data,
        headers=request_headers,
        method=method,
    )

    with urlrequest.urlopen(req, timeout=60) as response:
        return response.status, response.read()


def vt_verify_key(api_key):
    status, _ = vt_request(
        f"{VT_BASE}/users/me",
        api_key,
    )

    return 200 <= status < 300


def vt_lookup_file_hash(file_hash, api_key):
    return vt_request(
        f"{VT_BASE}/files/{file_hash}",
        api_key,
    )


def vt_get_upload_url(api_key):
    status, body = vt_request(
        f"{VT_BASE}/files/upload_url",
        api_key,
    )

    if not 200 <= status < 300:
        raise RuntimeError("VirusTotal could not provide an upload URL.")

    payload = json.loads(body.decode("utf-8"))

    upload_url = (
        payload.get("data")
        if isinstance(payload, dict)
        else None
    )

    if not upload_url:
        raise RuntimeError("VirusTotal returned an invalid upload URL.")

    return upload_url


def vt_upload_file(path, api_key):
    """
    Upload a file to VirusTotal.

    Files up to 32 MB use /files directly.
    Larger files use VirusTotal's upload URL endpoint.
    """

    file_size = os.path.getsize(path)

    if file_size > 32 * 1024 * 1024:
        upload_url = vt_get_upload_url(api_key)
    else:
        upload_url = f"{VT_BASE}/files"

    boundary = "----ZXAVBoundary7MA4YWxkTrZu0gW"

    filename = os.path.basename(path)

    with open(path, "rb") as file:
        file_data = file.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    ).encode("utf-8") + file_data + (
        f"\r\n--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    status, body = vt_request(
        upload_url,
        api_key,
        method="POST",
        data=body,
        headers=headers,
    )

    if not 200 <= status < 300:
        raise RuntimeError(
            f"VirusTotal upload failed with HTTP {status}."
        )

    payload = json.loads(body.decode("utf-8"))

    return (
        payload.get("data", {}).get("id")
        if isinstance(payload, dict)
        else None
    )


def vt_get_analysis(analysis_id, api_key):
    return vt_request(
        f"{VT_BASE}/analyses/{analysis_id}",
        api_key,
    )


def vt_submit_url(target_url, api_key):
    data = urlencode({
        "url": target_url
    }).encode("utf-8")

    status, body = vt_request(
        f"{VT_BASE}/urls",
        api_key,
        method="POST",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    if not 200 <= status < 300:
        raise RuntimeError(
            f"VirusTotal URL submission failed with HTTP {status}."
        )

    payload = json.loads(body.decode("utf-8"))

    return (
        payload.get("data", {}).get("id")
        if isinstance(payload, dict)
        else None
    )


# ========================================================
# Main application
# ========================================================

class ZXAVApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} — {APP_TAGLINE}")

        # Larger default window for 1440p / 4K displays.
        self.geometry("1440x900")
        self.minsize(1100, 700)

        self.configure(bg=BG)

        self._configure_scaling()
        self._configure_ttk()

        self.config_data = load_config()
        self.scan_history = load_scan_history()

        self.watchdog_job = None

        self.scan_thread = None
        self.scan_cancel_event = threading.Event()
        self.scan_in_progress = False

        self.progressbar = None
        self.progress_text = None
        self.cancel_button = None
        self.history_tree = None
        self.stats_labels = {}
        self.protection_canvas = None
        self.protection_text = None
        self.status_label = None

        self.protocol(
            "WM_DELETE_WINDOW",
            self._on_close,
        )

        self._show_startup_screen()

    # ====================================================
    # Display scaling
    # ====================================================

    def _configure_scaling(self):
        try:
            screen_width = self.winfo_screenwidth()

            if screen_width >= 3840:
                self.tk.call("tk", "scaling", 1.5)

            elif screen_width >= 2560:
                self.tk.call("tk", "scaling", 1.35)

            elif screen_width >= 1920:
                self.tk.call("tk", "scaling", 1.20)

        except tk.TclError:
            pass

    # ====================================================
    # ttk theme
    # ====================================================

    def _configure_ttk(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "ZX.TEntry",
            fieldbackground=PANEL_LIGHT,
            foreground=WHITE,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            insertcolor=WHITE,
            padding=8,
        )

        style.configure(
            "ZX.Horizontal.TProgressbar",
            troughcolor=PANEL_LIGHT,
            background=GREEN,
            bordercolor=PANEL_LIGHT,
            lightcolor=GREEN,
            darkcolor=GREEN,
            thickness=8,
        )

        style.configure(
            "ZX.Treeview",
            background=PANEL_LIGHT,
            foreground=TEXT,
            fieldbackground=PANEL_LIGHT,
            bordercolor=BORDER,
            rowheight=34,
            font=get_safe_font("Segoe UI", 9),
        )

        style.configure(
            "ZX.Treeview.Heading",
            background=PANEL,
            foreground=WHITE,
            bordercolor=BORDER,
            font=get_safe_font("Segoe UI", 9, "bold"),
            padding=8,
        )

        style.map(
            "ZX.Treeview",
            background=[
                ("selected", "#303337")
            ],
            foreground=[
                ("selected", WHITE)
            ],
        )

    # ====================================================
    # Generic UI helpers
    # ====================================================

    def clear_window(self):
        for widget in self.winfo_children():
            try:
                widget.destroy()
            except tk.TclError:
                pass

    def make_button(
        self,
        parent,
        text,
        command,
        width=None,
        primary=False,
    ):

        bg = PANEL_LIGHT if not primary else GREEN
        fg = WHITE if not primary else BG

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=PANEL_HOVER,
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=get_safe_font("Segoe UI", 9, "bold"),
            padx=14,
            pady=9,
        )

        if width:
            button.configure(width=width)

        return button

    def make_panel(self, parent, **kwargs):
        options = {
            "bg": PANEL,
            "highlightbackground": BORDER,
            "highlightcolor": BORDER,
            "highlightthickness": 1,
        }

        options.update(kwargs)

        return tk.Frame(parent, **options)

    # ====================================================
    # Startup splash screen
    # ====================================================

    def _show_startup_screen(self):

        self.clear_window()

        splash = tk.Frame(
            self,
            bg=BG,
        )

        splash.pack(
            fill="both",
            expand=True,
        )

        # ------------------------------------------------
        # Stage 1 — 5 seconds
        # ------------------------------------------------

        first_screen = tk.Frame(
            splash,
            bg=BG,
        )

        first_screen.pack(
            fill="both",
            expand=True,
        )

        tk.Label(
            first_screen,
            text="иди на хуй",
            bg=BG,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 32, "bold"),
        ).place(
            relx=0.5,
            rely=0.44,
            anchor="center",
        )

        tk.Label(
            first_screen,
            text="Loading ZX.AV...",
            bg=BG,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 10),
        ).place(
            relx=0.5,
            rely=0.54,
            anchor="center",
        )

        progress = ttk.Progressbar(
            first_screen,
            style="ZX.Horizontal.TProgressbar",
            mode="indeterminate",
            length=300,
        )

        progress.place(
            relx=0.5,
            rely=0.61,
            anchor="center",
        )

        progress.start(12)

        self.after(
            5000,
            lambda: self._show_second_splash(progress),
        )

    def _show_second_splash(self, old_progress):

        try:
            old_progress.stop()
        except tk.TclError:
            pass

        self.clear_window()

        # ------------------------------------------------
        # Stage 2 — 5 seconds
        # ------------------------------------------------

        second_screen = tk.Frame(
            self,
            bg=BG,
        )

        second_screen.pack(
            fill="both",
            expand=True,
        )

        tk.Label(
            second_screen,
            text="SECURED BY ZX.AI",
            bg=BG,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 25, "bold"),
        ).place(
            relx=0.5,
            rely=0.45,
            anchor="center",
        )

        tk.Label(
            second_screen,
            text="dolbayob",
            bg=BG,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 12, "bold"),
        ).place(
            relx=0.5,
            rely=0.54,
            anchor="center",
        )

        progress = ttk.Progressbar(
            second_screen,
            style="ZX.Horizontal.TProgressbar",
            mode="indeterminate",
            length=300,
        )

        progress.place(
            relx=0.5,
            rely=0.61,
            anchor="center",
        )

        progress.start(12)

        self.after(
            5000,
            lambda: self._finish_startup(progress),
        )

    def _finish_startup(self, progress):

        try:
            progress.stop()
        except tk.TclError:
            pass

        self._route_startup()

    # ====================================================
    # Startup routing
    # ====================================================

    def _route_startup(self):

        if self.config_data.get("license_key"):

            if license_is_expired(self.config_data):

                self.config_data.pop("license_key", None)
                self.config_data.pop("license_tier", None)
                self.config_data.pop("license_activated", None)
                self.config_data.pop("license_expiry", None)

                save_config(self.config_data)

                self._show_license_gate()
                return

        if not self.config_data.get("license_key"):
            self._show_license_gate()
            return

        if not self.config_data.get("vt_api_key"):
            self._show_api_key_gate()
            return

        self._build_main_ui()

    # ====================================================
    # License screen
    # ====================================================

    def _show_license_gate(self):

        self.clear_window()

        outer = tk.Frame(
            self,
            bg=BG,
        )

        outer.pack(
            fill="both",
            expand=True,
        )

        card = self.make_panel(
            outer,
            width=620,
            height=610,
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
        )

        tk.Label(
            card,
            text=APP_NAME,
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 30, "bold"),
        ).pack(pady=(40, 4))

        tk.Label(
            card,
            text=APP_TAGLINE,
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 10, "bold"),
        ).pack()

        tk.Label(
            card,
            text="Activate your license",
            bg=PANEL,
            fg=TEXT,
            font=get_safe_font("Segoe UI", 15, "bold"),
        ).pack(pady=(32, 8))

        tk.Label(
            card,
            text="Enter a valid ZX.AV license key to continue.",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 9),
        ).pack()

        key_var = tk.StringVar()

        entry = ttk.Entry(
            card,
            textvariable=key_var,
            style="ZX.TEntry",
            width=45,
        )

        entry.pack(
            pady=22,
            ipady=3,
        )

        entry.focus_set()

        status = tk.Label(
            card,
            text="",
            bg=PANEL,
            fg=RED,
            font=get_safe_font("Segoe UI", 9),
        )

        status.pack()

        def activate():

            key = key_var.get().strip().upper()

            license_keys = load_license_keys()
            tier = validate_license(key, license_keys)

            if not tier:
                status.configure(
                    text="Invalid or unsupported license key.",
                    fg=RED,
                )
                return

            used_keys = self.config_data.get(
                "used_license_keys",
                [],
            )

            if tier == "TRIAL" and key in used_keys:
                status.configure(
                    text="This trial key has already been used.",
                    fg=RED,
                )
                return

            activated_at = time.time()
            expiry = compute_expiry(
                tier,
                activated_at,
            )

            self.config_data["license_key"] = key
            self.config_data["license_tier"] = tier
            self.config_data["license_activated"] = activated_at
            self.config_data["license_expiry"] = expiry

            if tier == "TRIAL":
                used_keys.append(key)

            self.config_data["used_license_keys"] = used_keys

            save_config(self.config_data)

            self._show_api_key_gate()

        self.make_button(
            card,
            "Activate license",
            activate,
            primary=True,
        ).pack(
            pady=18,
            ipadx=15,
        )

        plans = tk.Frame(
            card,
            bg=PANEL,
        )

        plans.pack(
            fill="x",
            padx=35,
            pady=(18, 0),
        )

        for tier in (
            "TRIAL",
            "MONTHLY",
            "PRO",
            "LIFETIME",
        ):

            row = tk.Frame(
                plans,
                bg=PANEL_LIGHT,
            )

            row.pack(
                fill="x",
                pady=3,
            )

            tk.Label(
                row,
                text=TIER_LABELS[tier],
                bg=PANEL_LIGHT,
                fg=WHITE,
                font=get_safe_font("Segoe UI", 9, "bold"),
                width=16,
                anchor="w",
            ).pack(
                side="left",
                padx=12,
                pady=8,
            )

            tk.Label(
                row,
                text=TIER_DESCRIPTIONS[tier],
                bg=PANEL_LIGHT,
                fg=MUTED,
                font=get_safe_font("Segoe UI", 9),
                anchor="e",
            ).pack(
                side="right",
                padx=12,
            )

    # ====================================================
    # API key screen
    # ====================================================

    def _show_api_key_gate(self):

        self.clear_window()

        outer = tk.Frame(
            self,
            bg=BG,
        )

        outer.pack(
            fill="both",
            expand=True,
        )

        card = self.make_panel(
            outer,
            width=640,
            height=440,
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
        )

        tk.Label(
            card,
            text="VirusTotal connection",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 24, "bold"),
        ).pack(pady=(45, 8))

        tk.Label(
            card,
            text="Enter your VirusTotal API key.",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 10),
        ).pack()

        key_var = tk.StringVar(
            value=self.config_data.get(
                "vt_api_key",
                "",
            )
        )

        entry = ttk.Entry(
            card,
            textvariable=key_var,
            style="ZX.TEntry",
            width=52,
            show="•",
        )

        entry.pack(
            pady=28,
            ipady=4,
        )

        status = tk.Label(
            card,
            text="",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 9),
        )

        status.pack()

        def verify():

            key = key_var.get().strip()

            if not key:
                status.configure(
                    text="Enter an API key first.",
                    fg=RED,
                )
                return

            status.configure(
                text="Verifying key...",
                fg=MUTED,
            )

            def worker():

                try:
                    valid = vt_verify_key(key)

                    def result():

                        if valid:

                            self.config_data["vt_api_key"] = key
                            save_config(self.config_data)

                            self._build_main_ui()

                        else:
                            status.configure(
                                text="VirusTotal rejected this API key.",
                                fg=RED,
                            )

                    self.after(0, result)

                except Exception as exc:

                    self.after(
                        0,
                        lambda: status.configure(
                            text=f"Verification failed: {exc}",
                            fg=RED,
                        ),
                    )

            threading.Thread(
                target=worker,
                daemon=True,
            ).start()

        self.make_button(
            card,
            "Verify key",
            verify,
            primary=True,
        ).pack(
            ipadx=20,
        )

        tk.Label(
            card,
            text="Your API key is stored locally in your ZX.AV configuration.",
            bg=PANEL,
            fg=MUTED_DARK,
            font=get_safe_font("Segoe UI", 8),
        ).pack(
            pady=25,
        )

    # ====================================================
    # Main UI
    # ====================================================

    def _build_main_ui(self):

        self.clear_window()

        # ------------------------------------------------
        # Sidebar
        # ------------------------------------------------

        sidebar = tk.Frame(
            self,
            bg=SIDEBAR,
            width=230,
        )

        sidebar.pack(
            side="left",
            fill="y",
        )

        sidebar.pack_propagate(False)

        logo = tk.Frame(
            sidebar,
            bg=SIDEBAR,
        )

        logo.pack(
            fill="x",
            padx=20,
            pady=(28, 25),
        )

        tk.Label(
            logo,
            text="ZX.AV",
            bg=SIDEBAR,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 24, "bold"),
        ).pack(
            anchor="w",
        )

        tk.Label(
            logo,
            text=APP_TAGLINE,
            bg=SIDEBAR,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
            pady=(2, 0),
        )

        tk.Label(
            sidebar,
            text="WORKSPACE",
            bg=SIDEBAR,
            fg=MUTED_DARK,
            font=get_safe_font("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 8),
        )

        self._sidebar_button(
            sidebar,
            "Overview",
            self._build_main_ui,
        )

        self._sidebar_button(
            sidebar,
            "Scan file",
            self._scan_file_dialog,
        )

        self._sidebar_button(
            sidebar,
            "Scan directory",
            self._scan_directory_dialog,
        )

        self._sidebar_button(
            sidebar,
            "Scan URL",
            self._scan_url_dialog,
        )

        tk.Label(
            sidebar,
            text="APPLICATION",
            bg=SIDEBAR,
            fg=MUTED_DARK,
            font=get_safe_font("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
            padx=20,
            pady=(25, 8),
        )

        self._sidebar_button(
            sidebar,
            "Scan flow",
            self._show_scan_diagram,
        )

        self._sidebar_button(
            sidebar,
            "Settings",
            self._open_settings,
        )

        self._sidebar_button(
            sidebar,
            "What's new",
            self._show_changelog,
        )

        self._sidebar_button(
            sidebar,
            "About",
            self._show_about,
        )

        license_frame = tk.Frame(
            sidebar,
            bg=SIDEBAR,
        )

        license_frame.pack(
            side="bottom",
            fill="x",
            padx=20,
            pady=22,
        )

        tier = self.config_data.get(
            "license_tier",
            "UNKNOWN",
        )

        tk.Label(
            license_frame,
            text=TIER_LABELS.get(tier, tier),
            bg=SIDEBAR,
            fg=GREEN,
            font=get_safe_font("Segoe UI", 9, "bold"),
        ).pack(
            anchor="w",
        )

        self.license_expiry_label = tk.Label(
            license_frame,
            text=format_expiry(self.config_data),
            bg=SIDEBAR,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 8),
        )

        self.license_expiry_label.pack(
            anchor="w",
            pady=(3, 0),
        )

        # ------------------------------------------------
        # Main content
        # ------------------------------------------------

        content = tk.Frame(
            self,
            bg=BG,
        )

        content.pack(
            side="left",
            fill="both",
            expand=True,
        )

        # ------------------------------------------------
        # Header
        # ------------------------------------------------

        header = tk.Frame(
            content,
            bg=BG,
        )

        header.pack(
            fill="x",
            padx=35,
            pady=(28, 20),
        )

        header_left = tk.Frame(
            header,
            bg=BG,
        )

        header_left.pack(
            side="left",
        )

        tk.Label(
            header_left,
            text="Overview",
            bg=BG,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 24, "bold"),
        ).pack(
            anchor="w",
        )

        tk.Label(
            header_left,
            text=f"ZX.AV {APP_VERSION}",
            bg=BG,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 9),
        ).pack(
            anchor="w",
            pady=(3, 0),
        )

        header_right = tk.Frame(
            header,
            bg=BG,
        )

        header_right.pack(
            side="right",
        )

        tk.Label(
            header_right,
            text="● CONNECTED",
            bg=BG,
            fg=GREEN,
            font=get_safe_font("Segoe UI", 9, "bold"),
        ).pack(
            anchor="e",
        )

        self.license_header_label = tk.Label(
            header_right,
            text=format_expiry(self.config_data),
            bg=BG,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 8),
        )

        self.license_header_label.pack(
            anchor="e",
            pady=(4, 0),
        )

        # ------------------------------------------------
        # Scan panel
        # ------------------------------------------------

        scan_panel = self.make_panel(content)

        scan_panel.pack(
            fill="x",
            padx=35,
            pady=(0, 18),
        )

        scan_top = tk.Frame(
            scan_panel,
            bg=PANEL,
        )

        scan_top.pack(
            fill="x",
            padx=22,
            pady=(20, 12),
        )

        tk.Label(
            scan_top,
            text="Security scanner",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 13, "bold"),
        ).pack(
            side="left",
        )

        tk.Label(
            scan_top,
            text="Analyze a file, directory or URL",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 9),
        ).pack(
            side="left",
            padx=14,
        )

        actions = tk.Frame(
            scan_panel,
            bg=PANEL,
        )

        actions.pack(
            fill="x",
            padx=22,
            pady=(0, 16),
        )

        self.make_button(
            actions,
            "Scan file",
            self._scan_file_dialog,
            primary=True,
        ).pack(
            side="left",
            padx=(0, 8),
        )

        self.make_button(
            actions,
            "Scan directory",
            self._scan_directory_dialog,
        ).pack(
            side="left",
            padx=8,
        )

        self.make_button(
            actions,
            "Scan URL",
            self._scan_url_dialog,
        ).pack(
            side="left",
            padx=8,
        )

        self.cancel_button = self.make_button(
            actions,
            "Cancel scan",
            self._cancel_scan,
        )

        self.cancel_button.pack(
            side="right",
        )

        self.cancel_button.configure(
            state="disabled",
        )

        progress_row = tk.Frame(
            scan_panel,
            bg=PANEL,
        )

        progress_row.pack(
            fill="x",
            padx=22,
            pady=(0, 18),
        )

        self.progress_text = tk.StringVar(
            value="Ready",
        )

        tk.Label(
            progress_row,
            textvariable=self.progress_text,
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 8),
        ).pack(
            anchor="w",
            pady=(0, 7),
        )

        self.progressbar = ttk.Progressbar(
            progress_row,
            style="ZX.Horizontal.TProgressbar",
            mode="indeterminate",
        )

        self.progressbar.pack(
            fill="x",
        )

        # ------------------------------------------------
        # Stats
        # ------------------------------------------------

        stats = tk.Frame(
            content,
            bg=BG,
        )

        stats.pack(
            fill="x",
            padx=35,
            pady=(0, 18),
        )

        stat_specs = [
            ("total", "TOTAL SCANS"),
            ("clean", "CLEAN"),
            ("flagged", "FLAGGED"),
            ("errors", "ERRORS"),
            ("last", "LAST SCAN"),
        ]

        for column, (key, title) in enumerate(stat_specs):

            stats.grid_columnconfigure(
                column,
                weight=1,
            )

            card = self.make_panel(
                stats,
            )

            card.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=5,
            )

            tk.Label(
                card,
                text=title,
                bg=PANEL,
                fg=MUTED,
                font=get_safe_font("Segoe UI", 8, "bold"),
            ).pack(
                anchor="w",
                padx=16,
                pady=(14, 5),
            )

            value = tk.Label(
                card,
                text="0",
                bg=PANEL,
                fg=WHITE,
                font=get_safe_font("Segoe UI", 17, "bold"),
            )

            value.pack(
                anchor="w",
                padx=16,
                pady=(0, 14),
            )

            self.stats_labels[key] = value

        # ------------------------------------------------
        # Lower area
        # ------------------------------------------------

        lower = tk.Frame(
            content,
            bg=BG,
        )

        lower.pack(
            fill="both",
            expand=True,
            padx=35,
            pady=(0, 25),
        )

        # Protection panel

        protection = self.make_panel(lower)

        protection.pack(
            side="left",
            fill="y",
            padx=(0, 10),
        )

        tk.Label(
            protection,
            text="Protection overview",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 12, "bold"),
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10),
        )

        self.protection_canvas = tk.Canvas(
            protection,
            width=220,
            height=220,
            bg=PANEL,
            highlightthickness=0,
        )

        self.protection_canvas.pack(
            padx=15,
            pady=5,
        )

        self.protection_text = tk.Label(
            protection,
            text="No scans yet",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 9),
        )

        self.protection_text.pack(
            pady=(0, 20),
        )

        # History panel

        history = self.make_panel(lower)

        history.pack(
            side="left",
            fill="both",
            expand=True,
        )

        history_header = tk.Frame(
            history,
            bg=PANEL,
        )

        history_header.pack(
            fill="x",
            padx=20,
            pady=(18, 12),
        )

        tk.Label(
            history_header,
            text="Recent scans",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font("Segoe UI", 12, "bold"),
        ).pack(
            side="left",
        )

        self.make_button(
            history_header,
            "Export CSV",
            self._export_history_csv,
        ).pack(
            side="right",
            padx=(8, 0),
        )

        self.make_button(
            history_header,
            "Clear",
            self._clear_history,
        ).pack(
            side="right",
        )

        tree_frame = tk.Frame(
            history,
            bg=PANEL,
        )

        tree_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20),
        )

        columns = (
            "target",
            "type",
            "result",
            "detections",
            "size",
            "time",
        )

        self.history_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="ZX.Treeview",
        )

        headings = {
            "target": "Target",
            "type": "Type",
            "result": "Result",
            "detections": "Detections",
            "size": "Size",
            "time": "Time",
        }

        widths = {
            "target": 330,
            "type": 100,
            "result": 100,
            "detections": 100,
            "size": 100,
            "time": 150,
        }

        for column in columns:

            self.history_tree.heading(
                column,
                text=headings[column],
            )

            self.history_tree.column(
                column,
                width=widths[column],
                anchor="w",
            )

        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self.history_tree.yview,
        )

        self.history_tree.configure(
            yscrollcommand=scrollbar.set,
        )

        self.history_tree.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        self.history_tree.tag_configure(
            "clean",
            foreground=GREEN,
        )

        self.history_tree.tag_configure(
            "flagged",
            foreground=RED,
        )

        self.history_tree.tag_configure(
            "error",
            foreground=YELLOW,
        )

        # ------------------------------------------------
        # Status bar
        # ------------------------------------------------

        status_bar = tk.Frame(
            content,
            bg=SIDEBAR,
            height=28,
        )

        status_bar.pack(
            side="bottom",
            fill="x",
        )

        self.status_label = tk.Label(
            status_bar,
            text="Ready",
            bg=SIDEBAR,
            fg=MUTED,
            font=get_safe_font("Segoe UI", 8),
            anchor="w",
        )

        self.status_label.pack(
            fill="x",
            padx=15,
            pady=6,
        )

        self._populate_history_tree()
        self._refresh_stats()
        self._start_license_watchdog()

    # ====================================================
    # Sidebar button
    # ====================================================

    def _sidebar_button(self, parent, text, command):

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=SIDEBAR,
            fg=TEXT,
            activebackground=PANEL_HOVER,
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            cursor="hand2",
            anchor="w",
            font=get_safe_font("Segoe UI", 9),
            padx=20,
            pady=10,
        )

        button.pack(
            fill="x",
        )

        def on_enter(_event):
            if str(button["state"]) != "disabled":
                button.configure(
                    bg=PANEL_HOVER,
                    fg=WHITE,
                )

        def on_leave(_event):
            button.configure(
                bg=SIDEBAR,
                fg=TEXT,
            )

        button.bind(
            "<Enter>",
            on_enter,
        )

        button.bind(
            "<Leave>",
            on_leave,
        )

        return button

    # ====================================================
    # History
    # ====================================================

    def _populate_history_tree(self):

        if not self.history_tree:
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        for entry in reversed(self.scan_history):

            result = entry.get(
                "result",
                "ERROR",
            )

            tag = (
                "flagged"
                if result == "FLAGGED"
                else "clean"
                if result == "CLEAN"
                else "error"
            )

            self.history_tree.insert(
                "",
                "end",
                values=(
                    entry.get("target", "—"),
                    entry.get("type", "—"),
                    result,
                    entry.get("detections", 0),
                    entry.get("size", "—"),
                    entry.get("time", "—"),
                ),
                tags=(tag,),
            )

    def _record_result(
        self,
        target,
        scan_type,
        result,
        detections=0,
        size=None,
    ):

        if size is not None:
            size_display = format_bytes(size)
        else:
            size_display = "—"

        entry = {
            "target": target,
            "type": scan_type,
            "result": result,
            "detections": int(detections or 0),
            "size": size_display,
            "time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "timestamp": time.time(),
        }

        self.scan_history.append(entry)
        self.scan_history = self.scan_history[-MAX_HISTORY:]

        self.after(
            0,
            lambda: self._finish_record(entry),
        )

    def _finish_record(self, entry):

        save_scan_history(self.scan_history)

        if self.history_tree:

            result = entry["result"]

            tag = (
                "flagged"
                if result == "FLAGGED"
                else "clean"
                if result == "CLEAN"
                else "error"
            )

            self.history_tree.insert(
                "",
                0,
                values=(
                    entry["target"],
                    entry["type"],
                    result,
                    entry["detections"],
                    entry["size"],
                    entry["time"],
                ),
                tags=(tag,),
            )

            children = self.history_tree.get_children()

            if len(children) > MAX_HISTORY:
                for item in children[MAX_HISTORY:]:
                    self.history_tree.delete(item)

        self._refresh_stats()

    # ====================================================
    # Statistics
    # ====================================================

    def _refresh_stats(self):

        total = len(self.scan_history)

        clean = sum(
            1
            for entry in self.scan_history
            if entry.get("result") == "CLEAN"
        )

        flagged = sum(
            1
            for entry in self.scan_history
            if entry.get("result") == "FLAGGED"
        )

        errors = sum(
            1
            for entry in self.scan_history
            if entry.get("result") == "ERROR"
        )

        last = (
            self.scan_history[-1].get("result", "—")
            if self.scan_history
            else "—"
        )

        if "total" in self.stats_labels:
            self.stats_labels["total"].configure(
                text=str(total)
            )

        if "clean" in self.stats_labels:
            self.stats_labels["clean"].configure(
                text=str(clean),
                fg=GREEN,
            )

        if "flagged" in self.stats_labels:
            self.stats_labels["flagged"].configure(
                text=str(flagged),
                fg=RED if flagged else WHITE,
            )

        if "errors" in self.stats_labels:
            self.stats_labels["errors"].configure(
                text=str(errors),
                fg=YELLOW if errors else WHITE,
            )

        if "last" in self.stats_labels:
            self.stats_labels["last"].configure(
                text=last
            )

        self._draw_protection_ring(
            clean,
            flagged,
        )

    def _draw_protection_ring(
        self,
        clean,
        flagged,
    ):

        if not self.protection_canvas:
            return

        canvas = self.protection_canvas

        canvas.delete("all")

        total = clean + flagged

        cx = 110
        cy = 105

        if total == 0:

            canvas.create_oval(
                35,
                30,
                185,
                180,
                outline=BORDER_LIGHT,
                width=14,
            )

            canvas.create_text(
                cx,
                cy,
                text="—",
                fill=WHITE,
                font=get_safe_font(
                    "Segoe UI",
                    24,
                    "bold",
                ),
            )

            if self.protection_text:
                self.protection_text.configure(
                    text="No scans yet"
                )

            return

        clean_ratio = clean / total
        clean_extent = 360 * clean_ratio
        flagged_extent = 360 - clean_extent

        canvas.create_arc(
            35,
            30,
            185,
            180,
            start=90,
            extent=-clean_extent,
            style="arc",
            outline=GREEN,
            width=14,
        )

        if flagged > 0:
            canvas.create_arc(
                35,
                30,
                185,
                180,
                start=90 - clean_extent,
                extent=-flagged_extent,
                style="arc",
                outline=RED,
                width=14,
            )

        canvas.create_text(
            cx,
            cy - 7,
            text=str(total),
            fill=WHITE,
            font=get_safe_font(
                "Segoe UI",
                24,
                "bold",
            ),
        )

        canvas.create_text(
            cx,
            cy + 22,
            text="SCANS",
            fill=MUTED,
            font=get_safe_font(
                "Segoe UI",
                8,
                "bold",
            ),
        )

        if self.protection_text:

            self.protection_text.configure(
                text=(
                    f"{clean} clean  •  "
                    f"{flagged} flagged"
                )
            )

    # ====================================================
    # License watchdog
    # ====================================================

    def _start_license_watchdog(self):

        if self.watchdog_job:
            try:
                self.after_cancel(
                    self.watchdog_job
                )
            except tk.TclError:
                pass

        self._license_watchdog_tick()

    def _license_watchdog_tick(self):

        if license_is_expired(self.config_data):

            self.config_data.pop(
                "license_key",
                None,
            )

            self.config_data.pop(
                "license_tier",
                None,
            )

            self.config_data.pop(
                "license_activated",
                None,
            )

            self.config_data.pop(
                "license_expiry",
                None,
            )

            save_config(
                self.config_data
            )

            if self.scan_in_progress:
                self._cancel_scan()

            self._show_license_gate()
            return

        expiry_text = format_expiry(
            self.config_data
        )

        if hasattr(
            self,
            "license_header_label",
        ):
            try:
                self.license_header_label.configure(
                    text=expiry_text
                )
            except tk.TclError:
                pass

        if hasattr(
            self,
            "license_expiry_label",
        ):
            try:
                self.license_expiry_label.configure(
                    text=expiry_text
                )
            except tk.TclError:
                pass

        self.watchdog_job = self.after(
            1000,
            self._license_watchdog_tick,
        )

    # ====================================================
    # Settings
    # ====================================================

    def _open_settings(self):

        window = tk.Toplevel(self)

        window.title("ZX.AV Settings")
        window.geometry("650x500")
        window.minsize(550, 420)

        window.configure(bg=BG)

        tk.Label(
            window,
            text="Settings",
            bg=BG,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                22,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=30,
            pady=(28, 5),
        )

        tk.Label(
            window,
            text="Local ZX.AV configuration",
            bg=BG,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack(
            anchor="w",
            padx=30,
        )

        api_panel = self.make_panel(
            window,
        )

        api_panel.pack(
            fill="x",
            padx=30,
            pady=25,
        )

        tk.Label(
            api_panel,
            text="VirusTotal API key",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                10,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=18,
            pady=(18, 8),
        )

        key_var = tk.StringVar(
            value=self.config_data.get(
                "vt_api_key",
                "",
            )
        )

        entry = ttk.Entry(
            api_panel,
            textvariable=key_var,
            style="ZX.TEntry",
            show="•",
        )

        entry.pack(
            fill="x",
            padx=18,
            pady=(0, 12),
        )

        verify_status = tk.Label(
            api_panel,
            text="",
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                8,
            ),
        )

        verify_status.pack(
            anchor="w",
            padx=18,
            pady=(0, 10),
        )

        def verify():

            key = key_var.get().strip()

            if not key:
                verify_status.configure(
                    text="Enter an API key.",
                    fg=RED,
                )
                return

            verify_status.configure(
                text="Verifying...",
                fg=MUTED,
            )

            def worker():

                try:
                    valid = vt_verify_key(key)

                    def done():

                        if valid:

                            self.config_data[
                                "vt_api_key"
                            ] = key

                            save_config(
                                self.config_data
                            )

                            verify_status.configure(
                                text="API key verified.",
                                fg=GREEN,
                            )

                        else:

                            verify_status.configure(
                                text="API key rejected.",
                                fg=RED,
                            )

                    self.after(
                        0,
                        done,
                    )

                except Exception as exc:

                    self.after(
                        0,
                        lambda: verify_status.configure(
                            text=f"Verification failed: {exc}",
                            fg=RED,
                        ),
                    )

            threading.Thread(
                target=worker,
                daemon=True,
            ).start()

        self.make_button(
            api_panel,
            "Verify & save",
            verify,
            primary=True,
        ).pack(
            anchor="e",
            padx=18,
            pady=(0, 18),
        )

        license_panel = self.make_panel(
            window,
        )

        license_panel.pack(
            fill="x",
            padx=30,
        )

        tier = self.config_data.get(
            "license_tier",
            "UNKNOWN",
        )

        tk.Label(
            license_panel,
            text=f"License: {TIER_LABELS.get(tier, tier)}",
            bg=PANEL,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                10,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=18,
            pady=(15, 4),
        )

        tk.Label(
            license_panel,
            text=format_expiry(
                self.config_data
            ),
            bg=PANEL,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack(
            anchor="w",
            padx=18,
            pady=(0, 15),
        )

    # ====================================================
    # API key requirement
    # ====================================================

    def _require_api_key(self):

        key = self.config_data.get(
            "vt_api_key"
        )

        if not key:

            self._show_api_key_gate()
            return None

        return key

    # ====================================================
    # File scanning
    # ====================================================

    def _scan_file_dialog(self):

        if self.scan_in_progress:
            messagebox.showinfo(
                "Scan already running",
                "Please wait for the current scan to finish or cancel it.",
            )
            return

        api_key = self._require_api_key()

        if not api_key:
            return

        path = filedialog.askopenfilename(
            title="Select a file to scan",
        )

        if not path:
            return

        self._run_async(
            self._scan_file,
            path,
            api_key,
        )

    def _scan_file(self, path, api_key):

        try:

            self._set_status(
                f"Hashing {os.path.basename(path)}..."
            )

            self._set_progress_text(
                f"Hashing: {os.path.basename(path)}"
            )

            result, detections, size = self._scan_one_file(
                path,
                api_key,
            )

            self._record_result(
                path,
                "File",
                result,
                detections,
                size,
            )

            self._set_status(
                f"Scan complete: {result}"
            )

            self._set_progress_text(
                f"Complete: {result}"
            )

        except Exception as exc:

            self._record_result(
                path,
                "File",
                "ERROR",
                0,
                self._safe_file_size(path),
            )

            self._scan_error(
                str(exc)
            )

    # ====================================================
    # Shared file scanner
    # ====================================================

    def _scan_one_file(
        self,
        path,
        api_key,
    ):

        if self.scan_cancel_event.is_set():
            raise RuntimeError("Scan cancelled.")

        size = os.path.getsize(path)

        file_hash = sha256_of_file(path)

        if self.scan_cancel_event.is_set():
            raise RuntimeError("Scan cancelled.")

        self._set_status(
            f"Checking VirusTotal hash: {os.path.basename(path)}"
        )

        try:

            status, body = vt_lookup_file_hash(
                file_hash,
                api_key,
            )

            if status == 200:

                payload = json.loads(
                    body.decode("utf-8")
                )

                stats = (
                    payload
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = int(
                    stats.get("malicious", 0)
                    or 0
                )

                suspicious = int(
                    stats.get("suspicious", 0)
                    or 0
                )

                detections = malicious + suspicious

                result = (
                    "FLAGGED"
                    if detections > 0
                    else "CLEAN"
                )

                return result, detections, size

        except urlerror.HTTPError as exc:

            if exc.code != 404:
                raise

        self._set_status(
            f"Uploading {os.path.basename(path)} to VirusTotal..."
        )

        analysis_id = vt_upload_file(
            path,
            api_key,
        )

        if not analysis_id:
            raise RuntimeError(
                "VirusTotal did not return an analysis ID."
            )

        malicious, suspicious = self._poll_analysis(
            analysis_id,
            api_key,
        )

        detections = malicious + suspicious

        result = (
            "FLAGGED"
            if detections > 0
            else "CLEAN"
        )

        return result, detections, size

    def _safe_file_size(self, path):

        try:
            return os.path.getsize(path)
        except OSError:
            return None

    # ====================================================
    # Directory scanning
    # ====================================================

    def _scan_directory_dialog(self):

        if self.scan_in_progress:
            messagebox.showinfo(
                "Scan already running",
                "Please wait for the current scan to finish or cancel it.",
            )
            return

        api_key = self._require_api_key()

        if not api_key:
            return

        directory = filedialog.askdirectory(
            title="Select a directory to scan",
        )

        if not directory:
            return

        files = []

        self._set_status(
            "Collecting files..."
        )

        try:

            for root, dirs, filenames in os.walk(
                directory,
                followlinks=False,
            ):

                if self.scan_cancel_event.is_set():
                    return

                for filename in filenames:

                    path = os.path.join(
                        root,
                        filename,
                    )

                    if os.path.isfile(path):
                        files.append(path)

        except OSError as exc:

            messagebox.showerror(
                "Directory error",
                f"Could not read the directory:\n\n{exc}",
            )
            return

        if not files:

            messagebox.showinfo(
                "No files",
                "No files were found in this directory.",
            )
            return

        warning = messagebox.askyesno(
            "Directory scan",
            (
                f"Found {len(files):,} files.\n\n"
                "Files that are not already known to VirusTotal "
                "may be uploaded for analysis.\n\n"
                "Continue?"
            ),
        )

        if not warning:
            return

        self._run_async(
            self._scan_directory,
            directory,
            files,
            api_key,
        )

    def _scan_directory(
        self,
        directory,
        files,
        api_key,
    ):

        total = len(files)
        clean = 0
        flagged = 0
        errors = 0

        for index, path in enumerate(files, start=1):

            if self.scan_cancel_event.is_set():
                self._set_progress_text(
                    f"Cancelled after {index - 1:,} of {total:,} files"
                )
                break

            filename = os.path.basename(path)

            self._set_progress_text(
                f"Directory scan: {index:,}/{total:,} • {filename}"
            )

            self._set_status(
                f"Scanning {index:,}/{total:,}: {filename}"
            )

            try:

                result, detections, size = self._scan_one_file(
                    path,
                    api_key,
                )

                self._record_result(
                    path,
                    "Directory",
                    result,
                    detections,
                    size,
                )

                if result == "CLEAN":
                    clean += 1

                else:
                    flagged += 1

            except Exception as exc:

                if self.scan_cancel_event.is_set():
                    break

                errors += 1

                self._record_result(
                    path,
                    "Directory",
                    "ERROR",
                    0,
                    self._safe_file_size(path),
                )

                self._set_status(
                    f"Failed: {filename} — {exc}"
                )

        if self.scan_cancel_event.is_set():

            self._set_status(
                f"Directory scan cancelled • "
                f"{clean} clean • "
                f"{flagged} flagged • "
                f"{errors} errors"
            )

        else:

            self._set_status(
                f"Directory complete • "
                f"{clean} clean • "
                f"{flagged} flagged • "
                f"{errors} errors"
            )

            self._set_progress_text(
                (
                    f"Complete • {total:,} files • "
                    f"{clean} clean • "
                    f"{flagged} flagged • "
                    f"{errors} errors"
                )
            )

    # ====================================================
    # URL scanning
    # ====================================================

    def _scan_url_dialog(self):

        if self.scan_in_progress:
            messagebox.showinfo(
                "Scan already running",
                "Please wait for the current scan to finish or cancel it.",
            )
            return

        api_key = self._require_api_key()

        if not api_key:
            return

        window = tk.Toplevel(self)

        window.title("Scan URL")
        window.geometry("650x260")
        window.configure(bg=BG)
        window.transient(self)
        window.grab_set()

        tk.Label(
            window,
            text="Scan URL",
            bg=BG,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                20,
                "bold",
            ),
        ).pack(
            pady=(30, 8),
        )

        tk.Label(
            window,
            text="Enter the URL you want VirusTotal to analyze.",
            bg=BG,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack()

        url_var = tk.StringVar()

        entry = ttk.Entry(
            window,
            textvariable=url_var,
            style="ZX.TEntry",
            width=65,
        )

        entry.pack(
            padx=30,
            pady=22,
            ipady=4,
        )

        def start():

            target = url_var.get().strip()

            if not target:
                messagebox.showerror(
                    "Missing URL",
                    "Enter a URL first.",
                    parent=window,
                )
                return

            window.destroy()

            self._run_async(
                self._scan_url,
                target,
                api_key,
            )

        self.make_button(
            window,
            "Scan URL",
            start,
            primary=True,
        ).pack(
            ipadx=20,
        )

        entry.focus_set()

    def _scan_url(
        self,
        target,
        api_key,
    ):

        try:

            self._set_status(
                f"Submitting URL: {target}"
            )

            self._set_progress_text(
                "Submitting URL to VirusTotal..."
            )

            analysis_id = vt_submit_url(
                target,
                api_key,
            )

            if not analysis_id:
                raise RuntimeError(
                    "VirusTotal did not return an analysis ID."
                )

            malicious, suspicious = self._poll_analysis(
                analysis_id,
                api_key,
            )

            detections = malicious + suspicious

            result = (
                "FLAGGED"
                if detections > 0
                else "CLEAN"
            )

            self._record_result(
                target,
                "URL",
                result,
                detections,
                None,
            )

            self._set_status(
                f"URL scan complete: {result}"
            )

            self._set_progress_text(
                f"URL complete: {result}"
            )

        except Exception as exc:

            self._record_result(
                target,
                "URL",
                "ERROR",
                0,
                None,
            )

            self._scan_error(
                str(exc)
            )

    # ====================================================
    # Analysis polling
    # ====================================================

    def _poll_analysis(
        self,
        analysis_id,
        api_key,
        timeout=180,
    ):

        started = time.time()

        while True:

            if self.scan_cancel_event.is_set():
                raise RuntimeError(
                    "Scan cancelled."
                )

            if time.time() - started > timeout:
                raise TimeoutError(
                    "VirusTotal analysis timed out."
                )

            status, body = vt_get_analysis(
                analysis_id,
                api_key,
            )

            payload = json.loads(
                body.decode("utf-8")
            )

            attributes = (
                payload
                .get("data", {})
                .get("attributes", {})
            )

            analysis_status = attributes.get(
                "status",
                "queued",
            )

            if analysis_status == "completed":

                stats = attributes.get(
                    "stats",
                    {},
                )

                malicious = int(
                    stats.get("malicious", 0)
                    or 0
                )

                suspicious = int(
                    stats.get("suspicious", 0)
                    or 0
                )

                return malicious, suspicious

            self._set_status(
                f"VirusTotal analysis: {analysis_status}"
            )

            self._set_progress_text(
                f"VirusTotal analysis: {analysis_status}"
            )

            time.sleep(2)

    # ====================================================
    # Async / cancellation
    # ====================================================

    def _run_async(
        self,
        function,
        *args,
    ):

        if self.scan_in_progress:
            messagebox.showinfo(
                "Scan already running",
                "Another scan is already running.",
            )
            return

        self.scan_in_progress = True
        self.scan_cancel_event.clear()

        if self.progressbar:
            self.progressbar.start(12)

        if self.cancel_button:
            self.cancel_button.configure(
                state="normal"
            )

        self._set_progress_text(
            "Starting scan..."
        )

        def worker():

            try:
                function(*args)

            except Exception as exc:
                self.after(
                    0,
                    lambda: self._scan_error(
                        str(exc)
                    ),
                )

            finally:
                self.after(
                    0,
                    self._scan_finished,
                )

        self.scan_thread = threading.Thread(
            target=worker,
            daemon=True,
        )

        self.scan_thread.start()

    def _scan_finished(self):

        self.scan_in_progress = False
        self.scan_thread = None

        if self.progressbar:
            try:
                self.progressbar.stop()
            except tk.TclError:
                pass

        if self.cancel_button:
            self.cancel_button.configure(
                state="disabled"
            )

        if self.scan_cancel_event.is_set():

            self._set_progress_text(
                "Scan cancelled"
            )

        elif self.progress_text:

            current = self.progress_text.get()

            if not current.startswith("Complete"):
                self._set_progress_text(
                    "Ready"
                )

    def _cancel_scan(self):

        if not self.scan_in_progress:
            return

        self.scan_cancel_event.set()

        self._set_status(
            "Cancelling scan..."
        )

        self._set_progress_text(
            "Cancelling..."
        )

    # ====================================================
    # Status helpers
    # ====================================================

    def _set_status(self, text):

        def update():

            if self.status_label:

                try:
                    self.status_label.configure(
                        text=text
                    )
                except tk.TclError:
                    pass

        try:
            self.after(
                0,
                update,
            )
        except tk.TclError:
            pass

    def _set_progress_text(self, text):

        def update():

            if self.progress_text:

                try:
                    self.progress_text.set(
                        text
                    )
                except tk.TclError:
                    pass

        try:
            self.after(
                0,
                update,
            )
        except tk.TclError:
            pass

    def _scan_error(self, error_text):

        self._set_status(
            f"Scan error: {error_text}"
        )

        self._set_progress_text(
            "Scan error"
        )

    # ====================================================
    # Export history
    # ====================================================

    def _export_history_csv(self):

        if not self.scan_history:

            messagebox.showinfo(
                "Export history",
                "There is no scan history to export.",
            )

            return

        path = filedialog.asksaveasfilename(
            title="Export ZX.AV scan history",
            defaultextension=".csv",
            filetypes=[
                (
                    "CSV files",
                    "*.csv",
                ),
                (
                    "All files",
                    "*.*",
                ),
            ],
        )

        if not path:
            return

        try:

            with open(
                path,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "Target",
                        "Type",
                        "Result",
                        "Detections",
                        "Size",
                        "Time",
                    ],
                )

                writer.writeheader()

                for entry in self.scan_history:

                    writer.writerow({
                        "Target": entry.get(
                            "target",
                            "",
                        ),
                        "Type": entry.get(
                            "type",
                            "",
                        ),
                        "Result": entry.get(
                            "result",
                            "",
                        ),
                        "Detections": entry.get(
                            "detections",
                            0,
                        ),
                        "Size": entry.get(
                            "size",
                            "",
                        ),
                        "Time": entry.get(
                            "time",
                            "",
                        ),
                    })

            self._set_status(
                f"History exported to {path}"
            )

            messagebox.showinfo(
                "Export complete",
                "Scan history was exported successfully.",
            )

        except OSError as exc:

            messagebox.showerror(
                "Export failed",
                str(exc),
            )

    # ====================================================
    # Clear history
    # ====================================================

    def _clear_history(self):

        if not self.scan_history:
            return

        confirmed = messagebox.askyesno(
            "Clear history",
            "Delete all locally stored scan history?",
        )

        if not confirmed:
            return

        self.scan_history.clear()

        save_scan_history(
            self.scan_history
        )

        self._populate_history_tree()
        self._refresh_stats()

        self._set_status(
            "Scan history cleared."
        )

    # ====================================================
    # Scan-flow diagram
    # ====================================================

    def _show_scan_diagram(self):

        window = tk.Toplevel(self)

        window.title(
            "ZX.AV — Scan Flow"
        )

        window.geometry(
            "850x650"
        )

        window.minsize(
            700,
            550,
        )

        window.configure(
            bg=BG
        )

        tk.Label(
            window,
            text="ZX.AV Scan Flow",
            bg=BG,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                22,
                "bold",
            ),
        ).pack(
            pady=(25, 4),
        )

        tk.Label(
            window,
            text="How files, directories and URLs are analyzed",
            bg=BG,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack()

        canvas = tk.Canvas(
            window,
            bg=BG,
            highlightthickness=0,
        )

        canvas.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=25,
        )

        def draw():

            canvas.delete("all")

            width = canvas.winfo_width()

            if width < 100:
                return

            center = width / 2

            box_width = 230
            box_height = 58

            def box(
                x,
                y,
                text,
                subtitle=None,
            ):

                canvas.create_rectangle(
                    x - box_width / 2,
                    y - box_height / 2,
                    x + box_width / 2,
                    y + box_height / 2,
                    fill=PANEL_LIGHT,
                    outline=BORDER_LIGHT,
                    width=1,
                )

                canvas.create_text(
                    x,
                    y - 7,
                    text=text,
                    fill=WHITE,
                    font=get_safe_font(
                        "Segoe UI",
                        10,
                        "bold",
                    ),
                )

                if subtitle:

                    canvas.create_text(
                        x,
                        y + 14,
                        text=subtitle,
                        fill=MUTED,
                        font=get_safe_font(
                            "Segoe UI",
                            7,
                        ),
                    )

            def arrow(
                x1,
                y1,
                x2,
                y2,
            ):

                canvas.create_line(
                    x1,
                    y1,
                    x2,
                    y2,
                    fill=BORDER_LIGHT,
                    width=2,
                    arrow=tk.LAST,
                )

            # Top

            box(
                center,
                55,
                "SELECT TARGET",
                "File • Directory • URL",
            )

            # Three inputs

            branch_y = 150
            branch_gap = min(
                245,
                width / 3.3,
            )

            positions = [
                center - branch_gap,
                center,
                center + branch_gap,
            ]

            labels = [
                ("FILE", "Single file"),
                ("DIRECTORY", "Recursive files"),
                ("URL", "Web address"),
            ]

            for x, (title, subtitle) in zip(
                positions,
                labels,
            ):

                arrow(
                    center,
                    84,
                    x,
                    branch_y - 30,
                )

                box(
                    x,
                    branch_y,
                    title,
                    subtitle,
                )

            # Merge

            merge_y = 270

            for x in positions:

                arrow(
                    x,
                    branch_y + 30,
                    center,
                    merge_y - 30,
                )

            box(
                center,
                merge_y,
                "HASH / SUBMIT",
                "SHA-256 or VirusTotal submission",
            )

            # VT

            vt_y = 380

            arrow(
                center,
                merge_y + 30,
                center,
                vt_y - 30,
            )

            box(
                center,
                vt_y,
                "VIRUSTOTAL",
                "Multi-engine analysis",
            )

            # Result

            result_y = 490

            arrow(
                center,
                vt_y + 30,
                center,
                result_y - 30,
            )

            box(
                center,
                result_y,
                "RESULT",
                "Clean • Flagged • Error",
            )

            # History

            history_y = 590

            arrow(
                center,
                result_y + 30,
                center,
                history_y - 30,
            )

            box(
                center,
                history_y,
                "SCAN HISTORY",
                "Local history + CSV export",
            )

        canvas.bind(
            "<Configure>",
            lambda _event: draw(),
        )

        self.after(
            100,
            draw,
        )

    # ====================================================
    # About
    # ====================================================

    def _show_about(self):

        window = tk.Toplevel(self)

        window.title(
            f"About {APP_NAME}"
        )

        window.geometry(
            "580x430"
        )

        window.configure(
            bg=BG
        )

        tk.Label(
            window,
            text=APP_NAME,
            bg=BG,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                30,
                "bold",
            ),
        ).pack(
            pady=(40, 5),
        )

        tk.Label(
            window,
            text=APP_TAGLINE,
            bg=BG,
            fg=GREEN,
            font=get_safe_font(
                "Segoe UI",
                9,
                "bold",
            ),
        ).pack()

        tk.Label(
            window,
            text=f"Version {APP_VERSION}",
            bg=BG,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                10,
            ),
        ).pack(
            pady=(10, 25),
        )

        description = (
            "ZX.AV is a desktop security utility that uses "
            "VirusTotal for file and URL analysis.\n\n"
            "Version 2.1 adds recursive directory scanning, "
            "persistent history, CSV export, cancellation, "
            "high-resolution UI support and a visual scan-flow diagram."
        )

        tk.Label(
            window,
            text=description,
            bg=BG,
            fg=TEXT,
            justify="center",
            wraplength=480,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack(
            padx=35,
        )

        tk.Label(
            window,
            text="Built for ZX.AV",
            bg=BG,
            fg=MUTED_DARK,
            font=get_safe_font(
                "Segoe UI",
                8,
            ),
        ).pack(
            side="bottom",
            pady=25,
        )

    # ====================================================
    # Changelog
    # ====================================================

    def _show_changelog(self):

        window = tk.Toplevel(self)

        window.title(
            "ZX.AV — What's new"
        )

        window.geometry(
            "850x650"
        )

        window.configure(
            bg=BG
        )

        tk.Label(
            window,
            text="What's new",
            bg=BG,
            fg=WHITE,
            font=get_safe_font(
                "Segoe UI",
                22,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=25,
            pady=(25, 5),
        )

        tk.Label(
            window,
            text=f"ZX.AV {APP_VERSION}",
            bg=BG,
            fg=MUTED,
            font=get_safe_font(
                "Segoe UI",
                9,
            ),
        ).pack(
            anchor="w",
            padx=25,
        )

        text_frame = tk.Frame(
            window,
            bg=PANEL,
        )

        text_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20,
        )

        text_widget = tk.Text(
            text_frame,
            bg=PANEL,
            fg=TEXT,
            insertbackground=WHITE,
            selectbackground=PANEL_HOVER,
            relief="flat",
            bd=0,
            wrap="word",
            font=get_safe_font(
                "Consolas",
                9,
            ),
            padx=18,
            pady=18,
        )

        scrollbar = ttk.Scrollbar(
            text_frame,
            orient="vertical",
            command=text_widget.yview,
        )

        text_widget.configure(
            yscrollcommand=scrollbar.set,
        )

        text_widget.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        text_widget.insert(
            "1.0",
            load_changelog(),
        )

        text_widget.configure(
            state="disabled",
        )

    # ====================================================
    # Close
    # ====================================================

    def _on_close(self):

        if self.scan_in_progress:

            confirmed = messagebox.askyesno(
                "Scan running",
                "A scan is currently running. Exit ZX.AV anyway?",
            )

            if not confirmed:
                return

            self.scan_cancel_event.set()

        if self.watchdog_job:

            try:
                self.after_cancel(
                    self.watchdog_job
                )
            except tk.TclError:
                pass

        save_scan_history(
            self.scan_history
        )

        self.destroy()


# ========================================================
# Launch
# ========================================================

if __name__ == "__main__":
    app = ZXAVApp()
    app.mainloop()
