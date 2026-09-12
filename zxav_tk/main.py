from zxav.core.config import ensure_dirs
from zxav.ui_tk.app import App


def main():
    ensure_dirs()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
