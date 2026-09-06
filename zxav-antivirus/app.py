# ========================================================
# Startup splash screen
# ========================================================

def _show_startup_screen(self):

    self.clear_window()

    splash = tk.Frame(
        self,
        bg=BG
    )

    splash.pack(
        fill="both",
        expand=True
    )

    # ----------------------------------------------------
    # Stage 1 — 5 seconds
    # ----------------------------------------------------

    first_screen = tk.Frame(
        splash,
        bg=BG
    )

    first_screen.pack(
        fill="both",
        expand=True
    )

    tk.Label(
        first_screen,
        text="иди на хуй",
        bg=BG,
        fg=WHITE,
        font=(
            "Segoe UI",
            32,
            "bold"
        )
    ).place(
        relx=0.5,
        rely=0.44,
        anchor="center"
    )

    tk.Label(
        first_screen,
        text="Loading ZX.AV...",
        bg=BG,
        fg=MUTED,
        font=(
            "Segoe UI",
            9
        )
    ).place(
        relx=0.5,
        rely=0.54,
        anchor="center"
    )

    progress = ttk.Progressbar(
        first_screen,
        style="ZX.Horizontal.TProgressbar",
        mode="indeterminate",
        length=260
    )

    progress.place(
        relx=0.5,
        rely=0.61,
        anchor="center"
    )

    progress.start(12)

    # Exactly 5 seconds before stage 2.
    self.after(
        5000,
        lambda: self._show_second_splash(
            progress
        )
    )

def _show_second_splash(
    self,
    old_progress
):

    # Stop the existing progress bar BEFORE
    # destroying its parent widgets.
    try:
        old_progress.stop()
    except tk.TclError:
        pass

    self.clear_window()

    # ----------------------------------------------------
    # Stage 2 — 5 seconds
    # ----------------------------------------------------

    second_screen = tk.Frame(
        self,
        bg=BG
    )

    second_screen.pack(
        fill="both",
        expand=True
    )

    tk.Label(
        second_screen,
        text="SECURED BY ZX.AI",
        bg=BG,
        fg=WHITE,
        font=(
            "Segoe UI",
            25,
            "bold"
        )
    ).place(
        relx=0.5,
        rely=0.45,
        anchor="center"
    )

    tk.Label(
        second_screen,
        text="dolbayob",
        bg=BG,
        fg=MUTED,
        font=(
            "Segoe UI",
            12,
            "bold"
        )
    ).place(
        relx=0.5,
        rely=0.54,
        anchor="center"
    )

    progress = ttk.Progressbar(
        second_screen,
        style="ZX.Horizontal.TProgressbar",
        mode="indeterminate",
        length=260
    )

    progress.place(
        relx=0.5,
        rely=0.61,
        anchor="center"
    )

    progress.start(12)

    # Exactly another 5 seconds before the
    # normal application starts.
    self.after(
        5000,
        lambda: self._finish_startup(
            progress
        )
    )

def _finish_startup(
    self,
    progress
):

    try:
        progress.stop()
    except tk.TclError:
        pass

    self._route_startup()
