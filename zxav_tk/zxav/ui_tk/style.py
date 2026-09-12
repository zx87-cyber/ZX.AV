"""
Shared colors and a couple of small helpers so every screen looks
consistent without pulling in any styling framework.
"""
import tkinter as tk
from tkinter import ttk

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
GREEN = "#55B982"
RED = "#D96565"
YELLOW = "#C7A65B"

FONT = ("Helvetica", 9)
FONT_BOLD = ("Helvetica", 9, "bold")
FONT_TITLE = ("Helvetica", 20, "bold")
FONT_HEADING = ("Helvetica", 12, "bold")


def configure_ttk_theme(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Treeview", background=PANEL_LIGHT, foreground=TEXT,
                     fieldbackground=PANEL_LIGHT, rowheight=26, font=FONT)
    style.configure("Treeview.Heading", background=PANEL, foreground=WHITE, font=FONT_BOLD)
    style.map("Treeview", background=[("selected", "#303337")], foreground=[("selected", WHITE)])
    style.configure("TEntry", fieldbackground=PANEL_LIGHT, foreground=WHITE, padding=6)
    style.configure("TProgressbar", troughcolor=PANEL_LIGHT, background=GREEN)
    return style


def make_button(parent, text, command, primary=False, danger=False, **kwargs):
    if primary:
        bg, fg, active = GREEN, BG, "#63C793"
    elif danger:
        bg, fg, active = RED, BG, "#E68080"
    else:
        bg, fg, active = PANEL_LIGHT, WHITE, PANEL_HOVER
    button = tk.Button(
        parent, text=text, command=command, bg=bg, fg=fg,
        activebackground=active, activeforeground=fg,
        relief="flat", bd=0, cursor="hand2", font=FONT_BOLD,
        padx=12, pady=7,
    )
    for key, value in kwargs.items():
        button.configure(**{key: value})
    return button


def make_panel(parent, **kwargs):
    options = {"bg": PANEL, "highlightbackground": BORDER, "highlightthickness": 1}
    options.update(kwargs)
    return tk.Frame(parent, **options)


def make_entry(parent, textvariable=None, show=None, width=30):
    entry = tk.Entry(
        parent, textvariable=textvariable, bg=PANEL_LIGHT, fg=WHITE,
        insertbackground=WHITE, relief="flat", font=FONT, width=width,
        highlightbackground=BORDER, highlightthickness=1,
    )
    if show:
        entry.configure(show=show)
    return entry
