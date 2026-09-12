import tkinter as tk

from ..core.config import APP_NAME, load_config, save_config
from ..core.license_manager import license_is_expired, clear_license
from .style import BG, configure_ttk_theme
from .splash import show_splash
from .license_gate import build_license_gate
from .api_key_gate import build_api_key_gate
from .main_window import MainWindow


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1280x820")
        self.minsize(1040, 660)
        self.configure(bg=BG)
        configure_ttk_theme(self)

        self.config_data = load_config()
        self.current_page = None

        self.withdraw()
        show_splash(self, on_finished=self._start)

    def _start(self):
        self.deiconify()
        self._route()

    def _route(self):
        if self.config_data.get("license_key") and license_is_expired(self.config_data):
            clear_license(self.config_data)
            save_config(self.config_data)
        if not self.config_data.get("license_key"):
            self._show(build_license_gate(self, self.config_data, on_activated=self._route))
        elif not self.config_data.get("vt_api_key"):
            self._show(build_api_key_gate(self, self.config_data, on_verified=self._route))
        else:
            self._show(MainWindow(self, self.config_data, on_license_invalid=self._on_license_invalid))

    def _on_license_invalid(self):
        clear_license(self.config_data)
        save_config(self.config_data)
        self._route()

    def _show(self, frame):
        if self.current_page is not None:
            self.current_page.destroy()
        self.current_page = frame
        frame.pack(fill="both", expand=True)
