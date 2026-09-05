```python
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


# ============================================================
# ZX.AV
# Professional grey security utility
# ============================================================

APP_NAME = "ZX.AV"
APP_TAGLINE = "SECURED BY ZX.AI"
APP_VERSION = "2.0.0"


# ============================================================
# License
# ============================================================

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


# ============================================================
# Grey theme
# ============================================================

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

# Status colours only.
# These are deliberately NOT part of the main theme.
GREEN = "#55B982"
RED = "#D96565"
YELLOW = "#C7A65B"

CONFIG_DIR = os.path.join(
    os.path.expanduser("~"),
    ".zxav"
)

CONFIG_PATH = os.path.join(
    CONFIG_DIR,
    "config.json"
)

VT_BASE = "https://www.virustotal.com/api/v3"


# ============================================================
# Configuration / licensing
# ============================================================

def resource_path(relative_path):
    base_path = getattr(
        sys,
        "_MEIPASS",
        os.path.dirname(os.path.abspath(__file__))
    )
    return os.path.join(base_path, relative_path)


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    return {}


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def load_license_keys():
    try:
        with open(
            resource_path("license_keys.json"),
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)
    except Exception:
        return {}


def load_changelog():
    try:
        with open(
            resource_path("CHANGELOG.md"),
            "r",
            encoding="utf-8"
        ) as f:
            return f.read()
    except Exception:
        return "Changelog not available."


def validate_license(key):
    key = key.strip().upper()

    keys = load_license_keys()

    for tier, key_list in keys.items():
        if key in key_list:
            return tier

    return None


def compute_expiry(tier, activated_at):
    duration = TIER_DURATIONS.get(tier)

    if duration is None:
        return None

    return activated_at + duration


def license_is_expired(cfg):
    tier = cfg.get("license_tier")
    activated_at = cfg.get("activated_at")

    if not tier or not activated_at:
        return True

    expiry = compute_expiry(
        tier,
        activated_at
    )

    if expiry is None:
        return False

    return time.time() >= expiry


def format_expiry(tier, activated_at):
    expiry = compute_expiry(
        tier,
        activated_at
    )

    if expiry is None:
        return "No expiry"

    remaining = expiry - time.time()

    if remaining <= 0:
        return "Expired"

    if tier == "TRIAL":
        mins, secs = divmod(
            int(remaining),
            60
        )
        return f"Expires in {mins:02d}:{secs:02d}"

    return time.strftime(
        "Expires %d %b %Y",
        time.localtime(expiry)
    )


# ============================================================
# VirusTotal
# ============================================================

def vt_headers(api_key):
    return {
        "x-apikey": api_key,
        "Accept": "application/json",
    }


def vt_request(
    url,
    api_key,
    method="GET",
    data=None
):
    req = urlrequest.Request(
        url,
        method=method,
        headers=vt_headers(api_key),
        data=data
    )

    with urlrequest.urlopen(
        req,
        timeout=30
    ) as resp:
        return json.loads(
            resp.read().decode("utf-8")
        )


def sha256_of_file(
    path,
    chunk_size=1 << 20
):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def vt_lookup_file_hash(
    file_hash,
    api_key
):
    return vt_request(
        f"{VT_BASE}/files/{file_hash}",
        api_key
    )


def vt_upload_file(
    path,
    api_key
):
    boundary = "----ZXAVBoundary"

    filename = os.path.basename(path)

    with open(path, "rb") as f:
        file_bytes = f.read()

    body = bytearray()

    body += (
        f"--{boundary}\r\n"
    ).encode()

    body += (
        f'Content-Disposition: form-data; '
        f'name="file"; filename="{filename}"\r\n'
    ).encode()

    body += (
        b"Content-Type: "
        b"application/octet-stream\r\n\r\n"
    )

    body += file_bytes

    body += (
        f"\r\n--{boundary}--\r\n"
    ).encode()

    req = urlrequest.Request(
        f"{VT_BASE}/files",
        method="POST",
        data=bytes(body),
        headers={
            "x-apikey": api_key,
            "Content-Type":
                f"multipart/form-data; boundary={boundary}",
        },
    )

    with urlrequest.urlopen(
        req,
        timeout=120
    ) as resp:
        data = json.loads(
            resp.read().decode("utf-8")
        )

    return data["data"]["id"]


def vt_get_analysis(
    analysis_id,
    api_key
):
    return vt_request(
        f"{VT_BASE}/analyses/{analysis_id}",
        api_key
    )


def vt_submit_url(
    target_url,
    api_key
):
    body = f"url={target_url}".encode()

    req = urlrequest.Request(
        f"{VT_BASE}/urls",
        method="POST",
        data=body,
        headers={
            "x-apikey": api_key,
            "Content-Type":
                "application/x-www-form-urlencoded",
        },
    )

    with urlrequest.urlopen(
        req,
        timeout=30
    ) as resp:
        data = json.loads(
            resp.read().decode("utf-8")
        )

    return data["data"]["id"]


# ============================================================
# Application
# ============================================================

class ZXAVApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(
            f"{APP_NAME} — {APP_TAGLINE}"
        )

        self.geometry("1120x720")
        self.minsize(900, 600)

        self.configure(
            bg=BG
        )

        self.cfg = load_config()

        self.scan_history = []

        self.progress_animation = None

        self._configure_ttk()

        self._route_startup()

    # ========================================================
    # ttk styling
    # ========================================================

    def _configure_ttk(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "ZX.TEntry",
            fieldbackground=PANEL_LIGHT,
            foreground=WHITE,
            insertcolor=WHITE,
            borderwidth=0,
            padding=9,
        )

        style.configure(
            "ZX.Horizontal.TProgressbar",
            troughcolor=PANEL_LIGHT,
            background="#9A9DA1",
            bordercolor=PANEL_LIGHT,
            lightcolor="#9A9DA1",
            darkcolor="#9A9DA1",
        )

        style.configure(
            "ZX.Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            borderwidth=0,
            rowheight=34,
            font=("Segoe UI", 9),
        )

        style.configure(
            "ZX.Treeview.Heading",
            background=PANEL_LIGHT,
            foreground=MUTED,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
        )

        style.map(
            "ZX.Treeview",
            background=[
                ("selected", PANEL_HOVER)
            ],
            foreground=[
                ("selected", WHITE)
            ]
        )

    # ========================================================
    # Generic helpers
    # ========================================================

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def make_button(
        self,
        parent,
        text,
        command,
        primary=False,
        small=False
    ):
        if primary:
            bg = WHITE
            fg = BG
            active_bg = "#D0D0D0"
            active_fg = BG
        else:
            bg = PANEL_LIGHT
            fg = TEXT
            active_bg = PANEL_HOVER
            active_fg = WHITE

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=active_fg,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=(
                "Segoe UI",
                9 if small else 10,
                "bold" if primary else "normal"
            ),
            padx=(
                12 if small else 18
            ),
            pady=(
                7 if small else 10
            ),
        )

        return btn

    def make_panel(
        self,
        parent,
        padx=18,
        pady=18
    ):
        frame = tk.Frame(
            parent,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            bd=0
        )

        inner = tk.Frame(
            frame,
            bg=PANEL
        )

        inner.pack(
            fill="both",
            expand=True,
            padx=padx,
            pady=pady
        )

        return frame, inner

    def make_title(
        self,
        parent,
        text,
        size=20
    ):
        return tk.Label(
            parent,
            text=text,
            bg=parent.cget("bg"),
            fg=WHITE,
            font=(
                "Segoe UI",
                size,
                "bold"
            )
        )

    def make_muted(
        self,
        parent,
        text,
        size=9
    ):
        return tk.Label(
            parent,
            text=text,
            bg=parent.cget("bg"),
            fg=MUTED,
            font=(
                "Segoe UI",
                size
            )
        )

    # ========================================================
    # Startup routing
    # ========================================================

    def _route_startup(self):

        if license_is_expired(
            self.cfg
        ):

            had_license = bool(
                self.cfg.get(
                    "license_tier"
                )
            )

            self.cfg.pop(
                "license_tier",
                None
            )

            self.cfg.pop(
                "license_key",
                None
            )

            self.cfg.pop(
                "activated_at",
                None
            )

            save_config(
                self.cfg
            )

            self._show_license_gate(
                expired_message=(
                    "Your previous license expired. "
                    "Enter a new key to continue."
                    if had_license
                    else None
                )
            )

        elif not self.cfg.get(
            "vt_api_key"
        ):

            self._show_api_key_gate()

        else:

            self._build_main_ui()

    # ========================================================
    # License gate
    # ========================================================

    def _show_license_gate(
        self,
        expired_message=None
    ):

        self.clear_window()

        outer = tk.Frame(
            self,
            bg=BG
        )

        outer.pack(
            fill="both",
            expand=True
        )

        header = tk.Frame(
            outer,
            bg=BG
        )

        header.pack(
            fill="x",
            padx=45,
            pady=35
        )

        tk.Label(
            header,
            text="ZX.AV",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            header,
            text=APP_TAGLINE,
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            pady=(1, 0)
        )

        card = tk.Frame(
            outer,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            padx=45,
            pady=15,
            ipadx=35,
            ipady=30
        )

        tk.Label(
            card,
            text="License activation",
            bg=PANEL,
            fg=WHITE,
            font=("Segoe UI", 19, "bold")
        ).pack(
            anchor="w",
            padx=35
        )

        tk.Label(
            card,
            text=(
                "Enter your ZX.AV license key to unlock the application."
            ),
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            padx=35,
            pady=(5, 22)
        )

        if expired_message:

            tk.Label(
                card,
                text=expired_message,
                bg=PANEL,
                fg=RED,
                font=("Segoe UI", 9)
            ).pack(
                anchor="w",
                padx=35,
                pady=(0, 15)
            )

        tk.Label(
            card,
            text="LICENSE KEY",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=35,
            pady=(0, 5)
        )

        key_var = tk.StringVar()

        entry = tk.Entry(
            card,
            textvariable=key_var,
            bg=PANEL_LIGHT,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            bd=0,
            font=("Consolas", 11)
        )

        entry.pack(
            fill="x",
            padx=35,
            ipady=11
        )

        status = tk.Label(
            card,
            text="",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        )

        status.pack(
            anchor="w",
            padx=35,
            pady=(10, 0)
        )

        def activate():

            key = (
                key_var
                .get()
                .strip()
                .upper()
            )

            tier = validate_license(
                key
            )

            used_keys = self.cfg.get(
                "used_keys",
                []
            )

            if not tier:

                status.configure(
                    text="Key not recognized.",
                    fg=RED
                )

                return

            if key in used_keys:

                status.configure(
                    text="This key has already been activated on this device.",
                    fg=RED
                )

                return

            self.cfg[
                "license_tier"
            ] = tier

            self.cfg[
                "license_key"
            ] = key

            self.cfg[
                "activated_at"
            ] = time.time()

            used_keys.append(key)

            self.cfg[
                "used_keys"
            ] = used_keys

            save_config(
                self.cfg
            )

            self._route_startup()

        self.make_button(
            card,
            "Activate",
            activate,
            primary=True
        ).pack(
            anchor="e",
            padx=35,
            pady=20
        )

        entry.focus()

        entry.bind(
            "<Return>",
            lambda e: activate()
        )

    # ========================================================
    # API key setup
    # ========================================================

    def _show_api_key_gate(self):

        self.clear_window()

        root = tk.Frame(
            self,
            bg=BG
        )

        root.pack(
            fill="both",
            expand=True
        )

        header = tk.Frame(
            root,
            bg=BG
        )

        header.pack(
            fill="x",
            padx=45,
            pady=35
        )

        tk.Label(
            header,
            text="ZX.AV",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            header,
            text=APP_TAGLINE,
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w"
        )

        card = tk.Frame(
            root,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            padx=45,
            pady=15,
            ipadx=35,
            ipady=30
        )

        tk.Label(
            card,
            text="VirusTotal connection",
            bg=PANEL,
            fg=WHITE,
            font=("Segoe UI", 19, "bold")
        ).pack(
            anchor="w",
            padx=35
        )

        tk.Label(
            card,
            text=(
                "ZX.AV uses your VirusTotal API key to perform "
                "file and URL scans."
            ),
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=520,
            justify="left"
        ).pack(
            anchor="w",
            padx=35,
            pady=(5, 25)
        )

        tk.Label(
            card,
            text="API KEY",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=35,
            pady=(0, 5)
        )

        key_var = tk.StringVar(
            value=self.cfg.get(
                "vt_api_key",
                ""
            )
        )

        entry = tk.Entry(
            card,
            textvariable=key_var,
            show="•",
            bg=PANEL_LIGHT,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            bd=0,
            font=("Consolas", 10)
        )

        entry.pack(
            fill="x",
            padx=35,
            ipady=11
        )

        status = tk.Label(
            card,
            text="",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        )

        status.pack(
            anchor="w",
            padx=35,
            pady=10
        )

        buttons = tk.Frame(
            card,
            bg=PANEL
        )

        buttons.pack(
            fill="x",
            padx=35,
            pady=8
        )

        def verify():

            key = key_var.get().strip()

            if not key:

                status.configure(
                    text="Enter an API key first.",
                    fg=RED
                )

                return

            status.configure(
                text="Checking connection...",
                fg=MUTED
            )

            def worker():

                try:

                    vt_request(
                        f"{VT_BASE}/users/{key}",
                        key
                    )

                    self.after(
                        0,
                        lambda: status.configure(
                            text="Connection verified.",
                            fg=GREEN
                        )
                    )

                except urlerror.HTTPError as e:

                    msg = (
                        "Invalid API key."
                        if e.code in (401, 403)
                        else f"VirusTotal error ({e.code})."
                    )

                    self.after(
                        0,
                        lambda: status.configure(
                            text=msg,
                            fg=RED
                        )
                    )

                except Exception as e:

                    self.after(
                        0,
                        lambda: status.configure(
                            text=f"Connection failed: {e}",
                            fg=RED
                        )
                    )

            threading.Thread(
                target=worker,
                daemon=True
            ).start()

        def continue_setup():

            key = key_var.get().strip()

            if not key:

                status.configure(
                    text="Enter an API key first.",
                    fg=RED
                )

                return

            self.cfg[
                "vt_api_key"
            ] = key

            save_config(
                self.cfg
            )

            self._build_main_ui()

        self.make_button(
            buttons,
            "Verify",
            verify,
            small=True
        ).pack(
            side="left"
        )

        self.make_button(
            buttons,
            "Continue",
            continue_setup,
            primary=True
        ).pack(
            side="right"
        )

        entry.focus()

    # ========================================================
    # Main UI
    # ========================================================

    def _build_main_ui(self):

        self.clear_window()

        # ----------------------------------------------------
        # Sidebar
        # ----------------------------------------------------

        sidebar = tk.Frame(
            self,
            bg=SIDEBAR,
            width=215
        )

        sidebar.pack(
            side="left",
            fill="y"
        )

        sidebar.pack_propagate(False)

        logo = tk.Frame(
            sidebar,
            bg=SIDEBAR
        )

        logo.pack(
            fill="x",
            padx=22,
            pady=(27, 30)
        )

        tk.Label(
            logo,
            text="ZX.AV",
            bg=SIDEBAR,
            fg=WHITE,
            font=("Segoe UI", 22, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            logo,
            text=APP_TAGLINE,
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w"
        )

        # Navigation

        tk.Label(
            sidebar,
            text="WORKSPACE",
            bg=SIDEBAR,
            fg=MUTED_DARK,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 8)
        )

        self._sidebar_button(
            sidebar,
            "Overview",
            self._build_main_ui,
            active=True
        )

        self._sidebar_button(
            sidebar,
            "Scan file",
            self._scan_file_dialog
        )

        self._sidebar_button(
            sidebar,
            "Scan URL",
            self._scan_url_dialog
        )

        tk.Frame(
            sidebar,
            bg=BORDER,
            height=1
        ).pack(
            fill="x",
            padx=22,
            pady=20
        )

        tk.Label(
            sidebar,
            text="APPLICATION",
            bg=SIDEBAR,
            fg=MUTED_DARK,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 8)
        )

        self._sidebar_button(
            sidebar,
            "Settings",
            self._open_settings
        )

        self._sidebar_button(
            sidebar,
            "What's new",
            self._show_changelog
        )

        self._sidebar_button(
            sidebar,
            "About",
            self._show_about
        )

        # Sidebar bottom

        bottom = tk.Frame(
            sidebar,
            bg=SIDEBAR
        )

        bottom.pack(
            side="bottom",
            fill="x",
            padx=22,
            pady=22
        )

        tier = self.cfg.get(
            "license_tier",
            "UNKNOWN"
        )

        tk.Label(
            bottom,
            text="LICENSE",
            bg=SIDEBAR,
            fg=MUTED_DARK,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            bottom,
            text=TIER_LABELS.get(
                tier,
                tier
            ),
            bg=SIDEBAR,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

        # ----------------------------------------------------
        # Main content
        # ----------------------------------------------------

        main = tk.Frame(
            self,
            bg=BG
        )

        main.pack(
            side="left",
            fill="both",
            expand=True
        )

        # Header

        header = tk.Frame(
            main,
            bg=BG,
            height=78
        )

        header.pack(
            fill="x"
        )

        header.pack_propagate(False)

        title_area = tk.Frame(
            header,
            bg=BG
        )

        title_area.pack(
            side="left",
            padx=30,
            pady=18
        )

        tk.Label(
            title_area,
            text="Overview",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 19, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            title_area,
            text="File and URL security analysis",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )

        status_area = tk.Frame(
            header,
            bg=BG
        )

        status_area.pack(
            side="right",
            padx=25
        )

        api_set = bool(
            self.cfg.get(
                "vt_api_key"
            )
        )

        dot = "●"

        tk.Label(
            status_area,
            text=dot,
            bg=BG,
            fg=GREEN if api_set else RED,
            font=("Segoe UI", 9)
        ).pack(
            side="left"
        )

        tk.Label(
            status_area,
            text=(
                "Connected"
                if api_set
                else "Not connected"
            ),
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            side="left",
            padx=(5, 0)
        )

        # Content scroll-ish frame

        content = tk.Frame(
            main,
            bg=BG
        )

        content.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 25)
        )

        # ----------------------------------------------------
        # Scan area
        # ----------------------------------------------------

        scan_panel, scan = self.make_panel(
            content,
            padx=22,
            pady=20
        )

        scan_panel.pack(
            fill="x",
            pady=(0, 15)
        )

        tk.Label(
            scan,
            text="SCAN",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            scan,
            text="Analyze a file or URL",
            bg=PANEL,
            fg=WHITE,
            font=("Segoe UI", 15, "bold")
        ).pack(
            anchor="w",
            pady=(2, 4)
        )

        tk.Label(
            scan,
            text=(
                "Check your target against VirusTotal's "
                "multi-engine analysis."
            ),
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )

        actions = tk.Frame(
            scan,
            bg=PANEL
        )

        actions.pack(
            fill="x",
            pady=(18, 0)
        )

        self.make_button(
            actions,
            "Scan a file",
            self._scan_file_dialog,
            primary=True
        ).pack(
            side="left"
        )

        self.make_button(
            actions,
            "Scan a URL",
            self._scan_url_dialog
        ).pack(
            side="left",
            padx=(8, 0)
        )

        self.scan_progress = ttk.Progressbar(
            actions,
            style="ZX.Horizontal.TProgressbar",
            mode="indeterminate",
            length=190
        )

        self.scan_progress.pack(
            side="right",
            pady=4
        )

        # ----------------------------------------------------
        # Stats
        # ----------------------------------------------------

        stats = tk.Frame(
            content,
            bg=BG
        )

        stats.pack(
            fill="x",
            pady=(0, 15)
        )

        self.stat_labels = {}

        cards = [
            ("total", "TOTAL SCANS", "0"),
            ("clean", "CLEAN", "0"),
            ("flagged", "FLAGGED", "0"),
            ("last", "LAST SCAN", "—"),
        ]

        for i, (key, title, value) in enumerate(cards):

            card = tk.Frame(
                stats,
                bg=PANEL,
                highlightbackground=BORDER,
                highlightthickness=1
            )

            card.grid(
                row=0,
                column=i,
                sticky="nsew",
                padx=(
                    0 if i == 0 else 5,
                    5 if i < 3 else 0
                )
            )

            stats.columnconfigure(
                i,
                weight=1
            )

            tk.Label(
                card,
                text=title,
                bg=PANEL,
                fg=MUTED,
                font=("Segoe UI", 7, "bold")
            ).pack(
                anchor="w",
                padx=15,
                pady=(13, 0)
            )

            val = tk.Label(
                card,
                text=value,
                bg=PANEL,
                fg=WHITE,
                font=("Segoe UI", 17, "bold")
            )

            val.pack(
                anchor="w",
                padx=15,
                pady=(4, 13)
            )

            self.stat_labels[key] = val

        # ----------------------------------------------------
        # Lower panels
        # ----------------------------------------------------

        lower = tk.Frame(
            content,
            bg=BG
        )

        lower.pack(
            fill="both",
            expand=True
        )

        # Protection panel

        protection_panel = tk.Frame(
            lower,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            width=260
        )

        protection_panel.pack(
            side="left",
            fill="y",
            padx=(0, 8)
        )

        protection_panel.pack_propagate(False)

        tk.Label(
            protection_panel,
            text="PROTECTION",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=18,
            pady=(18, 0)
        )

        self.protection_canvas = tk.Canvas(
            protection_panel,
            width=180,
            height=180,
            bg=PANEL,
            highlightthickness=0
        )

        self.protection_canvas.pack(
            pady=5
        )

        self.protection_status = tk.Label(
            protection_panel,
            text="No scans yet",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        )

        self.protection_status.pack()

        # History

        history_panel = tk.Frame(
            lower,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        history_panel.pack(
            side="left",
            fill="both",
            expand=True
        )

        history_header = tk.Frame(
            history_panel,
            bg=PANEL
        )

        history_header.pack(
            fill="x",
            padx=18,
            pady=15
        )

        tk.Label(
            history_header,
            text="RECENT SCANS",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            side="left"
        )

        self.tree = ttk.Treeview(
            history_panel,
            style="ZX.Treeview",
            columns=(
                "target",
                "type",
                "result",
                "detections",
                "time"
            ),
            show="headings"
        )

        columns = [
            ("target", "Target", 260),
            ("type", "Type", 65),
            ("result", "Result", 90),
            ("detections", "Detections", 85),
            ("time", "Scanned", 135),
        ]

        for col, title, width in columns:

            self.tree.heading(
                col,
                text=title
            )

            self.tree.column(
                col,
                width=width,
                anchor="w"
            )

        self.tree.tag_configure(
            "clean",
            foreground=GREEN
        )

        self.tree.tag_configure(
            "flagged",
            foreground=RED
        )

        self.tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        self.status_var = tk.StringVar(
            value="Ready."
        )

        status_bar = tk.Frame(
            main,
            bg=SIDEBAR,
            height=30
        )

        status_bar.pack(
            fill="x",
            side="bottom"
        )

        status_bar.pack_propagate(False)

        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 8)
        ).pack(
            anchor="w",
            padx=15,
            pady=7
        )

        self._refresh_stats()

        self._start_license_watchdog()

    # ========================================================
    # Sidebar
    # ========================================================

    def _sidebar_button(
        self,
        parent,
        text,
        command,
        active=False
    ):

        bg = PANEL_LIGHT if active else SIDEBAR
        fg = WHITE if active else TEXT

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            anchor="w",
            bg=bg,
            fg=fg,
            activebackground=PANEL_HOVER,
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=("Segoe UI", 9),
            padx=22,
            pady=9
        )

        btn.pack(
            fill="x",
            padx=10,
            pady=1
        )

        return btn

    # ========================================================
    # Stats / graphics
    # ========================================================

    def _refresh_stats(self):

        total = len(
            self.scan_history
        )

        clean = sum(
            1
            for e in self.scan_history
            if e["result"] == "CLEAN"
        )

        flagged = sum(
            1
            for e in self.scan_history
            if e["result"] == "FLAGGED"
        )

        last = (
            self.scan_history[-1]["time"]
            if self.scan_history
            else "—"
        )

        self.stat_labels[
            "total"
        ].configure(
            text=str(total)
        )

        self.stat_labels[
            "clean"
        ].configure(
            text=str(clean)
        )

        self.stat_labels[
            "flagged"
        ].configure(
            text=str(flagged)
        )

        self.stat_labels[
            "last"
        ].configure(
            text=last
        )

        self._draw_protection_ring(
            clean,
            flagged
        )

    def _draw_protection_ring(
        self,
        clean,
        flagged
    ):

        c = self.protection_canvas

        c.delete("all")

        total = clean + flagged

        cx = 90
        cy = 82
        radius = 55

        bbox = (
            cx - radius,
            cy - radius,
            cx + radius,
            cy + radius
        )

        if total == 0:

            c.create_oval(
                *bbox,
                outline=BORDER_LIGHT,
                width=9
            )

            percent = "—"

        else:

            clean_ratio = clean / total

            clean_extent = (
                360 * clean_ratio
            )

            c.create_arc(
                *bbox,
                start=90,
                extent=-clean_extent,
                style="arc",
                outline=GREEN,
                width=9
            )

            c.create_arc(
                *bbox,
                start=90 - clean_extent,
                extent=-(360 - clean_extent),
                style="arc",
                outline=RED,
                width=9
            )

            percent = (
                f"{round(clean_ratio * 100)}%"
            )

        c.create_text(
            cx,
            cy - 5,
            text=percent,
            fill=WHITE,
            font=("Segoe UI", 18, "bold")
        )

        c.create_text(
            cx,
            cy + 18,
            text="clean",
            fill=MUTED,
            font=("Segoe UI", 8)
        )

        if total == 0:

            self.protection_status.configure(
                text="Waiting for first scan"
            )

        elif flagged:

            self.protection_status.configure(
                text=f"{flagged} flagged result(s)",
                fg=RED
            )

        else:

            self.protection_status.configure(
                text="No detections",
                fg=GREEN
            )

    # ========================================================
    # License watchdog
    # ========================================================

    def _start_license_watchdog(self):

        tier = self.cfg.get(
            "license_tier"
        )

        activated_at = self.cfg.get(
            "activated_at",
            0
        )

        def tick():

            if not self.winfo_exists():
                return

            if license_is_expired(
                self.cfg
            ):

                self._route_startup()
                return

            self.after(
                1000,
                tick
            )

        tick()

    # ========================================================
    # Settings
    # ========================================================

    def _open_settings(self):

        win = tk.Toplevel(self)

        win.title(
            "ZX.AV — Settings"
        )

        win.geometry(
            "560x430"
        )

        win.configure(
            bg=BG
        )

        win.transient(
            self
        )

        tk.Label(
            win,
            text="Settings",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 19, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(28, 3)
        )

        tk.Label(
            win,
            text="VirusTotal connection",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            padx=30
        )

        card = tk.Frame(
            win,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            fill="x",
            padx=30,
            pady=22
        )

        tk.Label(
            card,
            text="API KEY",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )

        key_var = tk.StringVar(
            value=self.cfg.get(
                "vt_api_key",
                ""
            )
        )

        entry = tk.Entry(
            card,
            textvariable=key_var,
            show="•",
            bg=PANEL_LIGHT,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            bd=0,
            font=("Consolas", 10)
        )

        entry.pack(
            fill="x",
            padx=20,
            ipady=10
        )

        status = tk.Label(
            card,
            text="",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9)
        )

        status.pack(
            anchor="w",
            padx=20,
            pady=10
        )

        def verify():

            key = key_var.get().strip()

            if not key:
                status.configure(
                    text="Enter an API key.",
                    fg=RED
                )
                return

            status.configure(
                text="Checking...",
                fg=MUTED
            )

            def worker():

                try:

                    vt_request(
                        f"{VT_BASE}/users/{key}",
                        key
                    )

                    self.after(
                        0,
                        lambda: status.configure(
                            text="API key verified.",
                            fg=GREEN
                        )
                    )

                except Exception:

                    self.after(
                        0,
                        lambda: status.configure(
                            text="Unable to verify API key.",
                            fg=RED
                        )
                    )

            threading.Thread(
                target=worker,
                daemon=True
            ).start()

        def save():

            key = key_var.get().strip()

            if not key:

                status.configure(
                    text="Enter an API key.",
                    fg=RED
                )

                return

            self.cfg[
                "vt_api_key"
            ] = key

            save_config(
                self.cfg
            )

            win.destroy()

            self._build_main_ui()

        buttons = tk.Frame(
            win,
            bg=BG
        )

        buttons.pack(
            fill="x",
            padx=30
        )

        self.make_button(
            buttons,
            "Verify",
            verify,
            small=True
        ).pack(
            side="left"
        )

        self.make_button(
            buttons,
            "Save",
            save,
            primary=True
        ).pack(
            side="right"
        )

    # ========================================================
    # File scan
    # ========================================================

    def _require_api_key(self):

        key = self.cfg.get(
            "vt_api_key"
        )

        if not key:

            messagebox.showwarning(
                "API key required",
                "Add your VirusTotal API key in Settings."
            )

            self._open_settings()

            return None

        return key

    def _scan_file_dialog(self):

        api_key = self._require_api_key()

        if not api_key:
            return

        path = filedialog.askopenfilename(
            title="Choose a file to scan"
        )

        if not path:
            return

        self._run_async(
            self._scan_file,
            path,
            api_key
        )

    def _scan_file(
        self,
        path,
        api_key
    ):

        name = os.path.basename(path)

        self._set_status(
            f"Hashing {name}..."
        )

        try:

            file_hash = sha256_of_file(
                path
            )

            self._set_status(
                "Checking VirusTotal..."
            )

            try:

                report = vt_lookup_file_hash(
                    file_hash,
                    api_key
                )

                stats = report[
                    "data"
                ][
                    "attributes"
                ][
                    "last_analysis_stats"
                ]

            except urlerror.HTTPError as e:

                if e.code != 404:
                    raise

                self._set_status(
                    "File not found in VirusTotal. Uploading..."
                )

                analysis_id = vt_upload_file(
                    path,
                    api_key
                )

                stats = self._poll_analysis(
                    analysis_id,
                    api_key
                )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            detections = (
                malicious +
                suspicious
            )

            result = (
                "FLAGGED"
                if detections > 0
                else "CLEAN"
            )

            self._record_result(
                name,
                "File",
                result,
                detections
            )

            self._set_status(
                f"{name}: {result} · "
                f"{detections} detections"
            )

        except Exception as e:

            self._scan_error(
                f"Scan failed: {e}"
            )

    # ========================================================
    # URL scan
    # ========================================================

    def _scan_url_dialog(self):

        api_key = self._require_api_key()

        if not api_key:
            return

        target = simpledialog.askstring(
            "Scan URL",
            "Enter the URL to check:",
            parent=self
        )

        if not target:
            return

        self._run_async(
            self._scan_url,
            target.strip(),
            api_key
        )

    def _scan_url(
        self,
        target,
        api_key
    ):

        try:

            self._set_status(
                f"Submitting URL..."
            )

            analysis_id = vt_submit_url(
                target,
                api_key
            )

            stats = self._poll_analysis(
                analysis_id,
                api_key
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            detections = (
                malicious +
                suspicious
            )

            result = (
                "FLAGGED"
                if detections > 0
                else "CLEAN"
            )

            self._record_result(
                target,
                "URL",
                result,
                detections
            )

            self._set_status(
                f"{target}: {result} · "
                f"{detections} detections"
            )

        except Exception as e:

            self._scan_error(
                f"Scan failed: {e}"
            )

    # ========================================================
    # Analysis polling
    # ========================================================

    def _poll_analysis(
        self,
        analysis_id,
        api_key,
        timeout=90,
        interval=3
    ):

        elapsed = 0

        while elapsed < timeout:

            data = vt_get_analysis(
                analysis_id,
                api_key
            )

            status = data[
                "data"
            ][
                "attributes"
            ][
                "status"
            ]

            if status == "completed":

                return data[
                    "data"
                ][
                    "attributes"
                ][
                    "stats"
                ]

            self._set_status(
                f"VirusTotal analysis: {status}"
            )

            time.sleep(
                interval
            )

            elapsed += interval

        raise TimeoutError(
            "VirusTotal analysis did not complete in time."
        )

    # ========================================================
    # History
    # ========================================================

    def _record_result(
        self,
        target,
        kind,
        result,
        detections
    ):

        entry = {
            "target": target,
            "type": kind,
            "result": result,
            "detections": detections,
            "time": time.strftime(
                "%Y-%m-%d %H:%M"
            ),
        }

        self.scan_history.append(
            entry
        )

        tag = (
            "flagged"
            if result == "FLAGGED"
            else "clean"
        )

        self.after(
            0,
            lambda: self.tree.insert(
                "",
                0,
                values=(
                    entry["target"],
                    entry["type"],
                    entry["result"],
                    entry["detections"],
                    entry["time"],
                ),
                tags=(tag,)
            )
        )

        self.after(
            0,
            self._refresh_stats
        )

    # ========================================================
    # Async / progress
    # ========================================================

    def _run_async(
        self,
        fn,
        *args
    ):

        self.scan_progress.start(
            12
        )

        def worker():

            try:
                fn(*args)

            finally:

                self.after(
                    0,
                    self.scan_progress.stop
                )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def _set_status(
        self,
        text
    ):

        self.after(
            0,
            lambda: self.status_var.set(
                text
            )
        )

    def _scan_error(
        self,
        message
    ):

        self._set_status(
            message
        )

        self.after(
            0,
            lambda: messagebox.showerror(
                "Scan error",
                message
            )
        )

    # ========================================================
    # About / changelog
    # ========================================================

    def _show_about(self):

        tier = self.cfg.get(
            "license_tier",
            "UNKNOWN"
        )

        messagebox.showinfo(
            "About ZX.AV",
            f"{APP_NAME}\n"
            f"{APP_TAGLINE}\n\n"
            f"Version {APP_VERSION}\n\n"
            "File and URL scanner powered by "
            "the VirusTotal API.\n\n"
            f"Plan: {TIER_LABELS.get(tier, tier)}"
        )

    def _show_changelog(self):

        win = tk.Toplevel(
            self
        )

        win.title(
            "ZX.AV — What's new"
        )

        win.geometry(
            "650x500"
        )

        win.configure(
            bg=BG
        )

        text = tk.Text(
            win,
            bg=PANEL,
            fg=TEXT,
            insertbackground=WHITE,
            selectbackground=PANEL_HOVER,
            font=("Consolas", 9),
            wrap="word",
            borderwidth=0,
            highlightthickness=0,
            padx=18,
            pady=18
        )

        text.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        text.insert(
            "1.0",
            load_changelog()
        )

        text.configure(
            state="disabled"
        )


# ============================================================
# Launch
# ============================================================

if __name__ == "__main__":

    app = ZXAVApp()

    app.mainloop()
```
