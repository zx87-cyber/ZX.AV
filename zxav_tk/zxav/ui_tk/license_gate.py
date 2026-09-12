import time
import tkinter as tk

from ..core.config import TIER_LABELS, TIER_DESCRIPTIONS, load_license_keys, save_config
from ..core.license_manager import validate_license, compute_expiry
from .style import BG, PANEL, WHITE, MUTED, RED, GREEN, FONT, FONT_BOLD, FONT_TITLE, make_button, make_entry


def build_license_gate(parent, config_data, on_activated):
    frame = tk.Frame(parent, bg=BG)

    card = tk.Frame(frame, bg=PANEL, highlightbackground="#2B2D30", highlightthickness=1)
    card.place(relx=0.5, rely=0.5, anchor="center", width=520, height=560)

    tk.Label(card, text="ZX.AV", bg=PANEL, fg=WHITE, font=FONT_TITLE).pack(pady=(36, 2))
    tk.Label(card, text="POWERED BY VIRUSTOTAL", bg=PANEL, fg=MUTED, font=("Helvetica", 8, "bold")).pack()
    tk.Label(card, text="Activate your license", bg=PANEL, fg=WHITE, font=FONT_BOLD).pack(pady=(24, 4))
    tk.Label(card, text="Enter a valid ZX.AV license key to continue.", bg=PANEL, fg=MUTED, font=FONT).pack()

    key_var = tk.StringVar()
    entry = make_entry(card, textvariable=key_var, width=32)
    entry.pack(pady=18, ipady=4)
    entry.focus_set()

    status = tk.Label(card, text="", bg=PANEL, fg=RED, font=("Helvetica", 8))
    status.pack()

    def activate():
        key = key_var.get().strip().upper()
        license_keys = load_license_keys()
        tier = validate_license(key, license_keys)
        if not tier:
            status.configure(text="Invalid or unsupported license key.")
            return
        used_keys = config_data.get("used_license_keys", [])
        if tier == "TRIAL" and key in used_keys:
            status.configure(text="This trial key has already been used.")
            return
        activated_at = time.time()
        config_data["license_key"] = key
        config_data["license_tier"] = tier
        config_data["license_activated"] = activated_at
        config_data["license_expiry"] = compute_expiry(tier, activated_at)
        if tier == "TRIAL":
            used_keys.append(key)
        config_data["used_license_keys"] = used_keys
        save_config(config_data)
        on_activated()

    entry.bind("<Return>", lambda _event: activate())
    make_button(card, "Activate license", activate, primary=True).pack(pady=6, ipadx=10)

    plans = tk.Frame(card, bg=PANEL)
    plans.pack(fill="x", padx=32, pady=(22, 0))
    for tier in ("TRIAL", "MONTHLY", "PRO", "LIFETIME"):
        row = tk.Frame(plans, bg="#202224")
        row.pack(fill="x", pady=3)
        tk.Label(row, text=TIER_LABELS[tier], bg="#202224", fg=WHITE, font=FONT_BOLD, width=14, anchor="w").pack(
            side="left", padx=10, pady=6)
        tk.Label(row, text=TIER_DESCRIPTIONS[tier], bg="#202224", fg=MUTED, font=FONT, anchor="e").pack(
            side="right", padx=10)

    return frame
