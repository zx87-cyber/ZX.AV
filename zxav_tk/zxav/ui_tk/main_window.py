import csv
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..core import history as history_store
from ..core import quarantine as quarantine_store
from ..core.config import APP_NAME, APP_VERSION, TIER_LABELS
from ..core.license_manager import format_expiry, license_is_expired
from ..core.reports import generate_html_report
from ..core.scanner import ScanEngine, ScanCancelled, format_bytes
from .engine_detail_window import show_engine_detail
from .style import (
    BG, SIDEBAR, PANEL, PANEL_LIGHT, PANEL_HOVER, WHITE, TEXT, MUTED, BORDER,
    GREEN, RED, YELLOW, FONT, FONT_BOLD, FONT_TITLE, FONT_HEADING,
    make_button, make_panel, make_entry,
)


class MainWindow(tk.Frame):
    def __init__(self, parent, config_data, on_license_invalid):
        super().__init__(parent, bg=BG)
        self.config_data = config_data
        self.on_license_invalid = on_license_invalid
        self.history = history_store.load_history()
        self.scan_thread = None
        self.cancel_event = threading.Event()
        self.quarantine_items = []
        self.stat_labels = {}

        self._build_sidebar()
        self._build_content()

        self._refresh_history()
        self._refresh_quarantine()
        self._watchdog_tick()

    # ------------------------------------------------------------------
    def _build_sidebar(self):
        sidebar = tk.Frame(self, bg=SIDEBAR, width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text=APP_NAME, bg=SIDEBAR, fg=WHITE, font=("Helvetica", 18, "bold")).pack(
            anchor="w", padx=18, pady=(22, 0))
        tk.Label(sidebar, text="POWERED BY VIRUSTOTAL", bg=SIDEBAR, fg=MUTED, font=("Helvetica", 7, "bold")).pack(
            anchor="w", padx=18, pady=(2, 20))

        self.nav_buttons = {}
        for label in ("Overview", "Scan", "History", "Quarantine", "Settings", "About"):
            button = tk.Button(
                sidebar, text=label, bg=SIDEBAR, fg=TEXT, activebackground=PANEL_HOVER,
                activeforeground=WHITE, relief="flat", bd=0, anchor="w", font=FONT,
                padx=18, pady=9, cursor="hand2", command=lambda l=label: self._navigate(l),
            )
            button.pack(fill="x")
            self.nav_buttons[label] = button

        tk.Frame(sidebar, bg=SIDEBAR).pack(fill="both", expand=True)

        tier = self.config_data.get("license_tier", "UNKNOWN")
        tk.Label(sidebar, text=TIER_LABELS.get(tier, tier), bg=SIDEBAR, fg=GREEN, font=FONT_BOLD).pack(
            anchor="w", padx=18, pady=(0, 0))
        self.expiry_label = tk.Label(sidebar, text=format_expiry(self.config_data), bg=SIDEBAR, fg=MUTED,
                                      font=("Helvetica", 7))
        self.expiry_label.pack(anchor="w", padx=18, pady=(2, 18))

    def _navigate(self, label):
        for name, button in self.nav_buttons.items():
            button.configure(bg=PANEL_HOVER if name == label else SIDEBAR, fg=WHITE if name == label else TEXT)
        self.pages[label].tkraise()
        if label == "History":
            self._refresh_history()
        if label == "Quarantine":
            self._refresh_quarantine()

    # ------------------------------------------------------------------
    def _build_content(self):
        content = tk.Frame(self, bg=BG)
        content.pack(side="left", fill="both", expand=True)

        pages_area = tk.Frame(content, bg=BG)
        pages_area.pack(fill="both", expand=True)
        pages_area.grid_rowconfigure(0, weight=1)
        pages_area.grid_columnconfigure(0, weight=1)

        self.pages = {}
        for label, builder in (
            ("Overview", self._build_overview_page),
            ("Scan", self._build_scan_page),
            ("History", self._build_history_page),
            ("Quarantine", self._build_quarantine_page),
            ("Settings", self._build_settings_page),
            ("About", self._build_about_page),
        ):
            page = builder(pages_area)
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[label] = page

        self.status_bar = tk.Label(content, text="Ready", bg=SIDEBAR, fg=MUTED, font=("Helvetica", 8), anchor="w")
        self.status_bar.pack(side="bottom", fill="x", ipady=5, padx=10)

        self._navigate("Overview")

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------
    def _build_overview_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Overview", bg=BG, fg=WHITE, font=FONT_TITLE).pack(anchor="w", padx=30, pady=(26, 0))
        tk.Label(page, text=f"{APP_NAME} {APP_VERSION}", bg=BG, fg=MUTED, font=FONT).pack(anchor="w", padx=30, pady=(2, 16))

        stats_row = tk.Frame(page, bg=BG)
        stats_row.pack(fill="x", padx=30, pady=(0, 14))
        for key, title in (("total", "TOTAL SCANS"), ("clean", "CLEAN"), ("flagged", "FLAGGED"), ("errors", "ERRORS")):
            card = make_panel(stats_row)
            card.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=("Helvetica", 7, "bold")).pack(anchor="w", padx=14, pady=(12, 2))
            value_label = tk.Label(card, text="0", bg=PANEL, fg=WHITE, font=("Helvetica", 16, "bold"))
            value_label.pack(anchor="w", padx=14, pady=(0, 12))
            self.stat_labels[key] = value_label

        lower = tk.Frame(page, bg=BG)
        lower.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        ring_panel = make_panel(lower)
        ring_panel.pack(side="left", fill="y", padx=(0, 8))
        tk.Label(ring_panel, text="Protection overview", bg=PANEL, fg=WHITE, font=FONT_HEADING).pack(
            anchor="w", padx=18, pady=(16, 8))
        self.ring_canvas = tk.Canvas(ring_panel, width=200, height=200, bg=PANEL, highlightthickness=0)
        self.ring_canvas.pack(padx=14, pady=4)
        self.ring_caption = tk.Label(ring_panel, text="No scans yet", bg=PANEL, fg=MUTED, font=("Helvetica", 8))
        self.ring_caption.pack(pady=(2, 16))

        recent_panel = make_panel(lower)
        recent_panel.pack(side="left", fill="both", expand=True)
        tk.Label(recent_panel, text="Recent scans", bg=PANEL, fg=WHITE, font=FONT_HEADING).pack(
            anchor="w", padx=18, pady=(16, 8))
        self.recent_tree = self._make_history_tree(recent_panel)
        self.recent_tree.pack(fill="both", expand=True, padx=14, pady=(0, 16))

        return page

    def _draw_ring(self, clean, flagged):
        canvas = self.ring_canvas
        canvas.delete("all")
        total = clean + flagged
        if total == 0:
            canvas.create_oval(20, 20, 180, 180, outline="#36383B", width=14)
            canvas.create_text(100, 96, text="\u2014", fill=WHITE, font=("Helvetica", 20, "bold"))
            self.ring_caption.configure(text="No scans yet")
            return
        clean_extent = 360 * (clean / total)
        flagged_extent = 360 - clean_extent
        canvas.create_arc(20, 20, 180, 180, start=90, extent=-clean_extent, style="arc", outline=GREEN, width=14)
        if flagged > 0:
            canvas.create_arc(20, 20, 180, 180, start=90 - clean_extent, extent=-flagged_extent, style="arc",
                               outline=RED, width=14)
        canvas.create_text(100, 90, text=str(total), fill=WHITE, font=("Helvetica", 20, "bold"))
        canvas.create_text(100, 112, text="SCANS", fill=MUTED, font=("Helvetica", 7, "bold"))
        self.ring_caption.configure(text=f"{clean} clean \u2022 {flagged} flagged")

    # ------------------------------------------------------------------
    # Scan page
    # ------------------------------------------------------------------
    def _build_scan_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Scan", bg=BG, fg=WHITE, font=FONT_TITLE).pack(anchor="w", padx=30, pady=(26, 0))
        tk.Label(page, text="Analyze a file, directory, or URL with VirusTotal", bg=BG, fg=MUTED, font=FONT).pack(
            anchor="w", padx=30, pady=(2, 16))

        panel = make_panel(page)
        panel.pack(fill="x", padx=30)

        tk.Label(panel, text="File or directory path", bg=PANEL, fg=MUTED, font=("Helvetica", 7, "bold")).pack(
            anchor="w", padx=18, pady=(18, 4))
        path_row = tk.Frame(panel, bg=PANEL)
        path_row.pack(fill="x", padx=18)
        self.path_var = tk.StringVar()
        make_entry(path_row, textvariable=self.path_var, width=40).pack(side="left", fill="x", expand=True, ipady=3)
        make_button(path_row, "Scan file", lambda: self._scan_file(), primary=True).pack(side="left", padx=(8, 0))
        make_button(path_row, "Scan directory", lambda: self._scan_directory()).pack(side="left", padx=(8, 0))

        tk.Label(panel, text="URL", bg=PANEL, fg=MUTED, font=("Helvetica", 7, "bold")).pack(
            anchor="w", padx=18, pady=(16, 4))
        url_row = tk.Frame(panel, bg=PANEL)
        url_row.pack(fill="x", padx=18)
        self.url_var = tk.StringVar()
        make_entry(url_row, textvariable=self.url_var, width=40).pack(side="left", fill="x", expand=True, ipady=3)
        make_button(url_row, "Scan URL", lambda: self._scan_url()).pack(side="left", padx=(8, 0))

        actions_row = tk.Frame(panel, bg=PANEL)
        actions_row.pack(fill="x", padx=18, pady=(16, 0))
        self.cancel_button = make_button(actions_row, "Cancel scan", self._cancel_scan, danger=True)
        self.cancel_button.pack(side="left")
        self.cancel_button.configure(state="disabled")

        self.progress_label = tk.Label(panel, text="Ready", bg=PANEL, fg=MUTED, font=("Helvetica", 8))
        self.progress_label.pack(anchor="w", padx=18, pady=(16, 6))
        self.progress_bar = ttk.Progressbar(panel, mode="indeterminate")
        self.progress_bar.pack(fill="x", padx=18, pady=(0, 18))

        return page

    # ------------------------------------------------------------------
    # History page
    # ------------------------------------------------------------------
    def _make_history_tree(self, parent, with_scrollbar=True):
        columns = ("target", "type", "result", "detections", "time")
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        headings = {"target": "Target", "type": "Type", "result": "Result", "detections": "Detections", "time": "Time"}
        widths = {"target": 280, "type": 80, "result": 80, "detections": 80, "time": 130}
        for column in columns:
            tree.heading(column, text=headings[column])
            tree.column(column, width=widths[column], anchor="w")
        tree.tag_configure("clean", foreground=GREEN)
        tree.tag_configure("flagged", foreground=RED)
        tree.tag_configure("error", foreground=YELLOW)
        tree.bind("<Double-1>", self._on_history_double_click)
        tree.bind("<Button-3>", self._on_history_right_click)
        return tree

    def _build_history_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="History", bg=BG, fg=WHITE, font=FONT_TITLE).pack(anchor="w", padx=30, pady=(26, 0))
        tk.Label(page, text="Double-click a row for per-engine results. Right-click to quarantine.",
                 bg=BG, fg=MUTED, font=FONT).pack(anchor="w", padx=30, pady=(2, 12))

        buttons_row = tk.Frame(page, bg=BG)
        buttons_row.pack(fill="x", padx=30, pady=(0, 10))
        make_button(buttons_row, "Export HTML report", self._export_html_report).pack(side="left")
        make_button(buttons_row, "Export CSV", self._export_csv).pack(side="left", padx=8)
        make_button(buttons_row, "Clear", self._clear_history, danger=True).pack(side="left")

        tree_frame = tk.Frame(page, bg=BG)
        tree_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        self.history_tree = self._make_history_tree(tree_frame)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return page

    def _on_history_double_click(self, event):
        tree = event.widget
        item = tree.identify_row(event.y)
        if not item:
            return
        entry = self._entry_for_row(tree, item)
        if entry:
            show_engine_detail(self, entry)

    def _on_history_right_click(self, event):
        tree = event.widget
        item = tree.identify_row(event.y)
        if not item:
            return
        tree.selection_set(item)
        entry = self._entry_for_row(tree, item)
        if not entry:
            return
        menu = tk.Menu(self, tearoff=0, bg=PANEL_LIGHT, fg=WHITE)
        if entry.get("result") == "FLAGGED" and entry.get("type") in ("File", "Directory"):
            menu.add_command(label="Quarantine this file", command=lambda: self._quarantine_entry(entry))
        else:
            menu.add_command(label="No actions available", state="disabled")
        menu.tk_popup(event.x_root, event.y_root)

    def _entry_for_row(self, tree, item):
        index = tree.index(item)
        entries = list(reversed(self.history))
        if 0 <= index < len(entries):
            return entries[index]
        return None

    def _quarantine_entry(self, entry):
        path = entry.get("target")
        if not path or not os.path.exists(path):
            messagebox.showwarning("Quarantine", "That file no longer exists on disk.")
            return
        if not messagebox.askyesno("Quarantine file", f"Move this file to quarantine?\n\n{path}"):
            return
        try:
            quarantine_store.quarantine_file(path, detections=entry.get("detections", 0))
            messagebox.showinfo("Quarantine", "File moved to quarantine.")
            self._refresh_quarantine()
        except OSError as exc:
            messagebox.showerror("Quarantine failed", str(exc))

    def _export_html_report(self):
        if not self.history:
            messagebox.showinfo("Export report", "There is no scan history to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", initialfile="zxav_report.html")
        if not path:
            return
        generate_html_report(self.history, path)
        messagebox.showinfo("Export complete", f"Report saved to:\n{path}")

    def _export_csv(self):
        if not self.history:
            messagebox.showinfo("Export CSV", "There is no scan history to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="zxav_history.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["Target", "Type", "Result", "Detections", "Size", "Time"])
            writer.writeheader()
            for entry in self.history:
                writer.writerow({
                    "Target": entry.get("target", ""), "Type": entry.get("type", ""),
                    "Result": entry.get("result", ""), "Detections": entry.get("detections", 0),
                    "Size": format_bytes(entry.get("size")), "Time": entry.get("time", ""),
                })
        messagebox.showinfo("Export complete", f"History exported to:\n{path}")

    def _clear_history(self):
        if not self.history:
            return
        if not messagebox.askyesno("Clear history", "Delete all locally stored scan history?"):
            return
        self.history = []
        history_store.save_history(self.history)
        self._refresh_history()

    # ------------------------------------------------------------------
    # Quarantine page
    # ------------------------------------------------------------------
    def _build_quarantine_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Quarantine", bg=BG, fg=WHITE, font=FONT_TITLE).pack(anchor="w", padx=30, pady=(26, 0))
        tk.Label(page, text="Files here have write/execute access stripped", bg=BG, fg=MUTED, font=FONT).pack(
            anchor="w", padx=30, pady=(2, 12))

        tree_frame = tk.Frame(page, bg=BG)
        tree_frame.pack(fill="both", expand=True, padx=30, pady=(0, 10))
        columns = ("path", "detections", "time")
        self.quarantine_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.quarantine_tree.heading("path", text="Original path")
        self.quarantine_tree.heading("detections", text="Detections")
        self.quarantine_tree.heading("time", text="Quarantined at")
        self.quarantine_tree.column("path", width=340)
        self.quarantine_tree.column("detections", width=90)
        self.quarantine_tree.column("time", width=150)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=scrollbar.set)
        self.quarantine_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        buttons_row = tk.Frame(page, bg=BG)
        buttons_row.pack(fill="x", padx=30, pady=(0, 20))
        make_button(buttons_row, "Restore selected", self._restore_quarantine_item).pack(side="left")
        make_button(buttons_row, "Delete permanently", self._delete_quarantine_item, danger=True).pack(
            side="left", padx=8)

        return page

    def _refresh_quarantine(self):
        self.quarantine_items = quarantine_store.list_items()
        for row in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(row)
        for item in self.quarantine_items:
            self.quarantine_tree.insert("", "end", values=(
                item.get("original_path", ""), item.get("detections", 0), item.get("quarantined_at", ""),
            ))

    def _selected_quarantine_item(self):
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Quarantine", "Select an item first.")
            return None
        index = self.quarantine_tree.index(selection[0])
        return self.quarantine_items[index]

    def _restore_quarantine_item(self):
        item = self._selected_quarantine_item()
        if not item:
            return
        try:
            destination = quarantine_store.restore_file(item["id"])
            messagebox.showinfo("Restored", f"File restored to:\n{destination}")
            self._refresh_quarantine()
        except (OSError, KeyError) as exc:
            messagebox.showerror("Restore failed", str(exc))

    def _delete_quarantine_item(self):
        item = self._selected_quarantine_item()
        if not item:
            return
        if not messagebox.askyesno("Delete permanently", "This cannot be undone. Continue?"):
            return
        try:
            quarantine_store.delete_permanently(item["id"])
            self._refresh_quarantine()
        except (OSError, KeyError) as exc:
            messagebox.showerror("Delete failed", str(exc))

    # ------------------------------------------------------------------
    # Settings page
    # ------------------------------------------------------------------
    def _build_settings_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Settings", bg=BG, fg=WHITE, font=FONT_TITLE).pack(anchor="w", padx=30, pady=(26, 16))

        panel = make_panel(page)
        panel.pack(fill="x", padx=30)
        tk.Label(panel, text="VirusTotal API key", bg=PANEL, fg=WHITE, font=FONT_BOLD).pack(
            anchor="w", padx=18, pady=(18, 6))
        self.settings_key_var = tk.StringVar(value=self.config_data.get("vt_api_key", ""))
        make_entry(panel, textvariable=self.settings_key_var, show="*", width=44).pack(
            anchor="w", padx=18, ipady=3)
        self.settings_status = tk.Label(panel, text="", bg=PANEL, fg=MUTED, font=("Helvetica", 8))
        self.settings_status.pack(anchor="w", padx=18, pady=(6, 0))
        make_button(panel, "Verify & save", self._verify_settings_key, primary=True).pack(
            anchor="e", padx=18, pady=18)

        license_panel = make_panel(page)
        license_panel.pack(fill="x", padx=30, pady=(16, 0))
        tier = self.config_data.get("license_tier", "UNKNOWN")
        tk.Label(license_panel, text=f"License: {TIER_LABELS.get(tier, tier)}", bg=PANEL, fg=WHITE,
                 font=FONT_BOLD).pack(anchor="w", padx=18, pady=(16, 2))
        self.settings_expiry_label = tk.Label(license_panel, text=format_expiry(self.config_data), bg=PANEL,
                                               fg=MUTED, font=FONT)
        self.settings_expiry_label.pack(anchor="w", padx=18, pady=(0, 16))

        return page

    def _verify_settings_key(self):
        key = self.settings_key_var.get().strip()
        if not key:
            self.settings_status.configure(text="Enter an API key.", fg=RED)
            return
        self.settings_status.configure(text="Verifying...", fg=MUTED)

        def worker():
            try:
                valid = vt_verify_key_safe(key)
                error = ""
            except Exception as exc:  # noqa: BLE001
                valid, error = False, str(exc)
            self.after(0, lambda: finish(valid, error))

        def finish(valid, error):
            if valid:
                self.config_data["vt_api_key"] = key
                from ..core.config import save_config
                save_config(self.config_data)
                self.settings_status.configure(text="API key verified and saved.", fg=GREEN)
            else:
                text = f"Verification failed: {error}" if error else "API key rejected."
                self.settings_status.configure(text=text, fg=RED)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # About page
    # ------------------------------------------------------------------
    def _build_about_page(self, parent):
        page = tk.Frame(parent, bg=BG)
        wrapper = tk.Frame(page, bg=BG)
        wrapper.place(relx=0.5, rely=0.4, anchor="center")
        tk.Label(wrapper, text=APP_NAME, bg=BG, fg=WHITE, font=("Helvetica", 26, "bold")).pack()
        tk.Label(wrapper, text=f"Version {APP_VERSION}", bg=BG, fg=MUTED, font=FONT).pack(pady=(4, 16))
        tk.Label(
            wrapper,
            text=("ZX.AV is a desktop security utility that uses VirusTotal for\n"
                  "file, directory, and URL analysis, with local quarantine and\n"
                  "per-engine detection reporting."),
            bg=BG, fg=MUTED, font=FONT, justify="center",
        ).pack()
        return page

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _api_key(self):
        key = self.config_data.get("vt_api_key")
        if not key:
            messagebox.showwarning("No API key", "Add a VirusTotal API key in Settings first.")
        return key

    def _scan_file(self):
        if self.scan_thread is not None:
            messagebox.showinfo("Scan running", "Please wait for the current scan to finish.")
            return
        api_key = self._api_key()
        if not api_key:
            return
        path = self.path_var.get().strip()
        if not path:
            path = filedialog.askopenfilename(title="Select a file to scan")
            if not path:
                return
            self.path_var.set(path)
        if not os.path.isfile(path):
            messagebox.showerror("Scan file", f"Not a file:\n{path}")
            return
        self._start_scan("file", path, api_key)

    def _scan_directory(self):
        if self.scan_thread is not None:
            messagebox.showinfo("Scan running", "Please wait for the current scan to finish.")
            return
        api_key = self._api_key()
        if not api_key:
            return
        directory = self.path_var.get().strip()
        if not directory:
            directory = filedialog.askdirectory(title="Select a directory to scan")
            if not directory:
                return
            self.path_var.set(directory)
        if not os.path.isdir(directory):
            messagebox.showerror("Scan directory", f"Not a directory:\n{directory}")
            return
        if not messagebox.askyesno(
            "Directory scan",
            "Files not already known to VirusTotal may be uploaded for analysis.\n\nContinue?",
        ):
            return
        self._start_scan("directory", directory, api_key)

    def _scan_url(self):
        if self.scan_thread is not None:
            messagebox.showinfo("Scan running", "Please wait for the current scan to finish.")
            return
        api_key = self._api_key()
        if not api_key:
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Scan URL", "Enter a URL first.")
            return
        self._start_scan("url", url, api_key)

    def _start_scan(self, kind, target, api_key):
        self.cancel_event = threading.Event()
        self.cancel_button.configure(state="normal")
        self.progress_bar.start(12)
        self._set_progress(f"Starting {kind} scan...")

        def worker():
            engine = ScanEngine(api_key, self.cancel_event, status_callback=lambda t: self.after(0, lambda: self._set_progress(t)))
            try:
                if kind == "file":
                    result = engine.scan_file(target)
                    self._record_result(result)
                elif kind == "url":
                    result = engine.scan_url(target)
                    self._record_result(result)
                elif kind == "directory":
                    for index, total, path in engine.iter_directory(target):
                        self.after(0, lambda i=index, t=total, p=path: self._set_progress(
                            f"Scanning {i:,}/{t:,}: {os.path.basename(p)}"))
                        try:
                            result = engine.scan_file(path)
                            result["type"] = "Directory"
                            self._record_result(result)
                        except ScanCancelled:
                            raise
                        except Exception:  # noqa: BLE001
                            self._record_result({
                                "id": None, "target": path, "type": "Directory", "size": None,
                                "result": "ERROR", "detections": 0, "total_engines": 0,
                                "time": time.strftime("%Y-%m-%d %H:%M:%S"), "timestamp": time.time(),
                                "permalink": None,
                            })
                self.after(0, self._scan_finished)
            except ScanCancelled:
                self.after(0, self._scan_finished)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self._scan_error(str(exc)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _record_result(self, result):
        self.after(0, lambda: self._finish_record(result))

    def _finish_record(self, result):
        self.history.append(result)
        history_store.save_history(self.history)
        self._refresh_history()
        self._set_status(f"Scan result: {result['result']} \u2014 {result.get('target', '')}")

    def _scan_finished(self):
        cancelled = self.cancel_event.is_set()
        self.scan_thread = None
        self.cancel_button.configure(state="disabled")
        self.progress_bar.stop()
        self._set_progress("Scan cancelled" if cancelled else "Ready")

    def _scan_error(self, message):
        self.scan_thread = None
        self.cancel_button.configure(state="disabled")
        self.progress_bar.stop()
        self._set_progress("Scan error")
        self._set_status(f"Scan error: {message}")
        messagebox.showerror("Scan error", message)

    def _cancel_scan(self):
        if self.scan_thread is not None:
            self.cancel_event.set()
            self._set_status("Cancelling scan...")

    # ------------------------------------------------------------------
    # Refresh helpers
    # ------------------------------------------------------------------
    def _refresh_history(self):
        entries = list(reversed(self.history))
        for tree, limit in ((self.history_tree, None), (self.recent_tree, 8)):
            for row in tree.get_children():
                tree.delete(row)
            shown = entries[:limit] if limit else entries
            for entry in shown:
                result = entry.get("result", "ERROR")
                tag = "flagged" if result == "FLAGGED" else "clean" if result == "CLEAN" else "error"
                tree.insert("", "end", values=(
                    entry.get("target", "\u2014"), entry.get("type", "\u2014"), result,
                    entry.get("detections", 0), entry.get("time", "\u2014"),
                ), tags=(tag,))

        stats = history_store.compute_stats(self.history)
        self.stat_labels["total"].configure(text=str(stats["total"]))
        self.stat_labels["clean"].configure(text=str(stats["clean"]), fg=GREEN)
        self.stat_labels["flagged"].configure(text=str(stats["flagged"]), fg=RED if stats["flagged"] else WHITE)
        self.stat_labels["errors"].configure(text=str(stats["errors"]), fg=YELLOW if stats["errors"] else WHITE)
        self._draw_ring(stats["clean"], stats["flagged"])

    def _set_status(self, text):
        self.status_bar.configure(text=text)

    def _set_progress(self, text):
        self.progress_label.configure(text=text)

    def _watchdog_tick(self):
        if license_is_expired(self.config_data):
            self.on_license_invalid()
            return
        expiry_text = format_expiry(self.config_data)
        self.expiry_label.configure(text=expiry_text)
        if hasattr(self, "settings_expiry_label"):
            self.settings_expiry_label.configure(text=expiry_text)
        self.after(1000, self._watchdog_tick)


def vt_verify_key_safe(key):
    from ..core.vt_api import vt_verify_key
    return vt_verify_key(key)
