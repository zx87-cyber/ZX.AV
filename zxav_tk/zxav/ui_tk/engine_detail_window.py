import tkinter as tk
from tkinter import ttk

from ..core.history import load_detail
from .style import BG, WHITE, MUTED, GREEN, RED, FONT, FONT_BOLD


def show_engine_detail(parent, entry):
    window = tk.Toplevel(parent)
    window.title(f"Engine results \u2014 {entry.get('target', '')}")
    window.geometry("560x600")
    window.configure(bg=BG)

    tk.Label(window, text=entry.get("target", ""), bg=BG, fg=WHITE, font=FONT_BOLD,
             wraplength=520, justify="left").pack(anchor="w", padx=20, pady=(18, 2))
    tk.Label(
        window,
        text=f"{entry.get('detections', 0)} / {entry.get('total_engines', 0)} engines flagged this {entry.get('type', 'item').lower()}",
        bg=BG, fg=MUTED, font=FONT,
    ).pack(anchor="w", padx=20)

    tree_frame = tk.Frame(window, bg=BG)
    tree_frame.pack(fill="both", expand=True, padx=20, pady=16)

    columns = ("engine", "verdict", "signature")
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
    tree.heading("engine", text="Engine")
    tree.heading("verdict", text="Verdict")
    tree.heading("signature", text="Signature")
    tree.column("engine", width=160)
    tree.column("verdict", width=100)
    tree.column("signature", width=220)

    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    tree.tag_configure("flagged", foreground=RED)
    tree.tag_configure("clean", foreground=GREEN)

    detail = load_detail(entry["id"]) if entry.get("id") else {"engines": {}, "permalink": None}
    engines = detail.get("engines", {})
    flagged_categories = {"malicious", "suspicious"}
    rows = sorted(engines.items(), key=lambda kv: (0 if kv[1].get("category") in flagged_categories else 1, kv[0].lower()))
    for name, info in rows:
        category = info.get("category", "undetected")
        tag = "flagged" if category in flagged_categories else "clean"
        tree.insert("", "end", values=(name, category, info.get("result") or "\u2014"), tags=(tag,))

    if detail.get("permalink"):
        link = tk.Label(window, text="View full report on VirusTotal", bg=BG, fg=GREEN,
                         font=("Helvetica", 8, "underline"), cursor="hand2")
        link.pack(anchor="w", padx=20, pady=(0, 16))
        import webbrowser
        link.bind("<Button-1>", lambda _e: webbrowser.open(detail["permalink"]))
