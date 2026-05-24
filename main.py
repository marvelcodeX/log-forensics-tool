"""
main.py
-------
Entry point for the Log Forensics Tool.
"""

from ui.app import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()