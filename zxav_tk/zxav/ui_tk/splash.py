"""
Plain tkinter splash screen. Fades using the window's -alpha attribute,
which every major Tk build on Linux/Windows/macOS supports.
"""
import tkinter as tk

BG = "#101112"
WHITE = "#F1F1F1"
GREEN = "#55B982"
MUTED = "#8C8F93"


def show_splash(root, on_finished, hold_ms=1400, step_ms=25):
    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.configure(bg=BG)
    width, height = 480, 260
    splash.geometry(f"{width}x{height}")
    splash.update_idletasks()
    screen_w = splash.winfo_screenwidth()
    screen_h = splash.winfo_screenheight()
    splash.geometry(f"+{(screen_w - width) // 2}+{(screen_h - height) // 2}")

    try:
        splash.attributes("-alpha", 0.0)
        alpha_supported = True
    except tk.TclError:
        alpha_supported = False

    tk.Label(splash, text="Welcome to ZX.AV", bg=BG, fg=WHITE,
             font=("Helvetica", 22, "bold")).pack(pady=(60, 6))
    tk.Label(splash, text="Built by ZX Industries", bg=BG, fg=GREEN,
             font=("Helvetica", 10, "bold")).pack()
    tk.Label(splash, text="Starting up...", bg=BG, fg=MUTED,
             font=("Helvetica", 8)).pack(pady=(30, 0))

    def fade(value, direction, next_action):
        if not alpha_supported:
            next_action()
            return
        value += direction * 0.05
        value = max(0.0, min(1.0, value))
        try:
            splash.attributes("-alpha", value)
        except tk.TclError:
            next_action()
            return
        if (direction > 0 and value < 1.0) or (direction < 0 and value > 0.0):
            splash.after(step_ms, lambda: fade(value, direction, next_action))
        else:
            next_action()

    def start_hold():
        splash.after(hold_ms, start_fade_out)

    def start_fade_out():
        fade(1.0, -1, finish)

    def finish():
        splash.destroy()
        on_finished()

    fade(0.0, 1, start_hold)
