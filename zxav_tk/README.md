# ZX.AV (tkinter desktop)

## Run it

```bash
python3 main.py
```

That's it — no pip install. Everything here is Python standard library.

## One-time system requirement

tkinter is Python's standard GUI toolkit, but most Linux distros ship it
as a separate OS package rather than bundling it with Python itself.
Install it once with:

```bash
# Debian / Ubuntu / Mint
sudo apt install python3-tk

# Fedora / RHEL / CentOS
sudo dnf install python3-tkinter

# Arch / Manjaro
sudo pacman -S tk
```

You'll also need:
- `license_keys.json` next to `main.py` (already included, with a working
  test key: `TEST-KEY` \u2192 `LIFETIME`).
- A VirusTotal API key, entered on first run.

## What's here

- Splash screen: fades in "Welcome to ZX.AV / Built by ZX Industries",
  holds, fades out.
- Scan file, directory, or URL against VirusTotal (background thread,
  UI stays responsive, cancel button works).
- History with double-click for per-engine (multi-vendor) results,
  right-click to quarantine a flagged file, HTML/CSV export, clear.
- Quarantine: flagged files get moved out and write access stripped;
  restore or permanently delete from the Quarantine tab.
- Overview tab: stat cards plus a canvas-drawn protection ring.
- Same license-tier gate and VirusTotal API key gate as before.

## How this was verified

I don't have tkinter importable in my own sandbox either (same root
cause as before — no network to install system packages there). So
instead of shipping this blind, I built a minimal fake `tkinter` module
and used it to actually *execute* this app's code: constructed the full
window, navigated every page, ran a scan through the real UI code path
with a mocked VirusTotal response, did a full quarantine round-trip
(add/restore) against a real temp file, and exercised all three startup
routing branches (license gate / API key gate / main window).

That catches real Python bugs (wrong variable names, bad method calls,
broken control flow) but can't confirm real Tk rendering/layout, since
the stub doesn't draw anything. So there's still a real chance of a
cosmetic layout issue or a genuine Tk API mismatch I can't see from
here. If something looks off visually or throws on launch, send me the
exact error and I'll fix it fast.
