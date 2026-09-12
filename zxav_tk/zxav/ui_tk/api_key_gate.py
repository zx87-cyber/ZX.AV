import threading
import tkinter as tk

from ..core.config import save_config
from ..core.vt_api import vt_verify_key
from .style import BG, PANEL, WHITE, MUTED, RED, GREEN, FONT, FONT_BOLD, make_button, make_entry


def build_api_key_gate(parent, config_data, on_verified):
    frame = tk.Frame(parent, bg=BG)

    card = tk.Frame(frame, bg=PANEL, highlightbackground="#2B2D30", highlightthickness=1)
    card.place(relx=0.5, rely=0.5, anchor="center", width=520, height=380)

    tk.Label(card, text="VirusTotal connection", bg=PANEL, fg=WHITE, font=("Helvetica", 16, "bold")).pack(pady=(36, 4))
    tk.Label(card, text="Enter your VirusTotal API key.", bg=PANEL, fg=MUTED, font=FONT).pack()

    key_var = tk.StringVar(value=config_data.get("vt_api_key", ""))
    entry = make_entry(card, textvariable=key_var, show="*", width=36)
    entry.pack(pady=20, ipady=4)

    status = tk.Label(card, text="", bg=PANEL, fg=MUTED, font=("Helvetica", 8))
    status.pack()

    verify_button = None

    def verify():
        key = key_var.get().strip()
        if not key:
            status.configure(text="Enter an API key first.", fg=RED)
            return
        status.configure(text="Verifying key...", fg=MUTED)
        verify_button.configure(state="disabled")

        def worker():
            try:
                valid = vt_verify_key(key)
                error = ""
            except Exception as exc:  # noqa: BLE001
                valid, error = False, str(exc)
            parent.after(0, lambda: finish(valid, error))

        def finish(valid, error):
            verify_button.configure(state="normal")
            if valid:
                config_data["vt_api_key"] = key
                save_config(config_data)
                on_verified()
            else:
                text = f"Verification failed: {error}" if error else "VirusTotal rejected this API key."
                status.configure(text=text, fg=RED)

        threading.Thread(target=worker, daemon=True).start()

    entry.bind("<Return>", lambda _event: verify())
    verify_button = make_button(card, "Verify key", verify, primary=True)
    verify_button.pack(pady=6, ipadx=10)

    tk.Label(card, text="Your API key is stored locally in your ZX.AV configuration.",
             bg=PANEL, fg=MUTED, font=("Helvetica", 7), wraplength=420).pack(pady=(24, 0))

    return frame
