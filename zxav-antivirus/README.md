# ZX.AV — Secured by ZX.AI

A lightweight desktop scanner that checks files and URLs against
[VirusTotal](https://www.virustotal.com), which aggregates results from
70+ real antivirus engines. This project does not include its own malware
detection engine — it's a client for VirusTotal's public API, so every
result you see is a real result from real AV vendors.

License keys (bundled in `license_keys.json`) gate access locally and set
the displayed plan tier (TRIAL / MONTHLY / PRO / LIFETIME).

## What you need

1. A free VirusTotal account and API key: https://www.virustotal.com/gui/join-us
   (Settings → API Key, after logging in). The public API has a rate limit
   (4 requests/minute on the free tier) — fine for personal use, not for
   bulk scanning.
2. A GitHub account, to let GitHub Actions build the Windows `.exe` for you.

## Running it from source (any OS, for testing)

```bash
python app.py
```

No third-party packages are required to *run* it — just Python 3.9+ with
tkinter (included in standard Python installs on Windows/Mac; on Linux you
may need `sudo apt install python3-tk`).

## Building the .exe on GitHub (no local Windows machine needed)

**Option A — no command line, using the GitHub website:**
1. Create a new repository at github.com (click **+** → New repository).
2. On the empty repo page, click **uploading an existing file**, then
   drag in every file and folder from this project (make sure `.github`
   comes along — it holds the build instructions).
3. Click **Commit changes**.
4. Go to the **Actions** tab — a build starts automatically. When it's
   green, open it, scroll to **Artifacts**, and download `ZXAV-windows-exe`.

**Option B — using git on the command line:**
1. Create a new GitHub repository and push this project to it:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```
2. Go to your repo's **Actions** tab on GitHub. The `Build ZX.AV Windows
   executable` workflow (`.github/workflows/build-exe.yml`) runs
   automatically on every push to `main`, using GitHub's free
   `windows-latest` runner and PyInstaller.
3. When the run finishes (green check), open it and scroll to
   **Artifacts** — download `ZXAV-windows-exe`. Unzip it to get `ZXAV.exe`.
4. You can also trigger a build manually any time from the Actions tab
   via **Run workflow** (this is enabled by the `workflow_dispatch` line
   in the workflow file).

The `.exe` is built fresh from your source each time — nothing is
pre-compiled or hidden.

## First run

- On first launch, the app asks for a license key — it's checked against
  `license_keys.json` bundled with the app.
- Next it asks for your VirusTotal API key, with a **Verify key** button
  that checks it live. It's saved locally to
  `%USERPROFILE%\.zxav\config.json` (Windows) — never sent anywhere
  except to VirusTotal's own API when you scan something.
- The dashboard has a menu bar (**File / Scan / View / Help**), stat
  cards, a protection ring, and a detections chart that all update as
  you scan.

## What's new

See [CHANGELOG.md](./CHANGELOG.md) — updated every time a new feature is
added. It's also viewable inside the app from **Help → What's new**.

## Notes on VirusTotal's limits

- Free API keys are rate-limited (4 req/min, ~500/day). If you scan a lot,
  consider VirusTotal's paid tiers.
- Uploading a brand-new file (one VT has never seen) takes longer than
  looking up a hash VT already has a report for — the app handles both
  cases automatically.
- This tool doesn't do real-time/on-access protection (that requires a
  kernel-level driver, which is a much larger undertaking) — it's an
  on-demand scanner.
