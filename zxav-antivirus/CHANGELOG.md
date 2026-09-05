# ZX.AV changelog

All notable changes to ZX.AV are tracked here. This file is bundled into
the app and viewable from the Help menu.

## [1.3.0]
### Added
- Real tier enforcement, so each license key actually expires:
  - **Trial** — 10 minutes, single use (key is burned after one activation)
  - **Member** (monthly key) — 1 month from activation
  - **Member Plus** (pro key) — 1 year from activation
  - **Lifetime** — never expires
- Live countdown / expiry date shown on the dashboard header
- App automatically returns to the license screen the moment a key expires
- Used keys are remembered on-device so a burned key can't be reactivated
- License screen now lists all four plans and their durations

## [1.2.0]
### Added
- Menu bar (File, Scan, View, Help)
- Protection ring diagram (clean vs flagged share of all scans)
- Detections bar chart (most recent scans, by detection count)
- In-app changelog viewer (Help \u2192 What's new)
- Version number shown on the main dashboard

## [1.1.0]
### Added
- Dashboard stat cards: Total scans, Clean, Flagged, Last scan
- Stats update live as scans complete

## [1.0.0]
### Added
- Local license key activation screen (TRIAL / MONTHLY / PRO / LIFETIME)
- VirusTotal API key setup screen with live "Verify key" check
- File scanning via VirusTotal (hash lookup, falls back to upload for
  files VT hasn't seen before)
- URL scanning via VirusTotal
- Scan history table
- GitHub Actions workflow to build a Windows .exe automatically
