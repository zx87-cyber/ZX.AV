"""
Paths, constants, and JSON persistence helpers shared across ZX.AV.
"""
import json
import os
import sys

APP_NAME = "ZX.AV"
APP_TAGLINE = "Powered by VirusTotal"
APP_VERSION = "3.0.0"

# ------------------------------------------------------------------
# License tiers
# ------------------------------------------------------------------
TIER_DURATIONS = {
    "TRIAL": 10 * 60,
    "MONTHLY": 30 * 24 * 3600,
    "PRO": 365 * 24 * 3600,
    "LIFETIME": None,
}
TIER_LABELS = {
    "TRIAL": "Trial",
    "MONTHLY": "Member",
    "PRO": "Member Plus",
    "LIFETIME": "Lifetime",
}
TIER_DESCRIPTIONS = {
    "TRIAL": "10 minutes, single use",
    "MONTHLY": "1 month",
    "PRO": "1 year",
    "LIFETIME": "Never expires",
}

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zxav")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
HISTORY_PATH = os.path.join(CONFIG_DIR, "scan_history.json")
DETAILS_DIR = os.path.join(CONFIG_DIR, "details")
QUARANTINE_DIR = os.path.join(CONFIG_DIR, "quarantine")
QUARANTINE_INDEX_PATH = os.path.join(CONFIG_DIR, "quarantine_index.json")
SCHEDULES_PATH = os.path.join(CONFIG_DIR, "schedules.json")
MONITORS_PATH = os.path.join(CONFIG_DIR, "monitors.json")
REPORTS_DIR = os.path.join(CONFIG_DIR, "reports")

MAX_HISTORY = 2000
VT_BASE = "https://www.virustotal.com/api/v3"


def ensure_dirs():
    for path in (CONFIG_DIR, DETAILS_DIR, QUARANTINE_DIR, REPORTS_DIR):
        os.makedirs(path, exist_ok=True)


def resource_path(relative_path):
    """Path that works both run normally and packaged (PyInstaller)."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..")))
    return os.path.join(base_path, relative_path)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_atomic(path, data):
    ensure_dirs()
    temp_path = path + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
        os.replace(temp_path, path)
    except OSError:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass


def load_config():
    ensure_dirs()
    data = load_json(CONFIG_PATH, {})
    return data if isinstance(data, dict) else {}


def save_config(config):
    save_json_atomic(CONFIG_PATH, config)


def load_license_keys():
    for path in (
        resource_path("license_keys.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "license_keys.json"),
    ):
        if os.path.exists(path):
            data = load_json(path, {})
            if isinstance(data, dict):
                return data
    return {}


def load_changelog():
    for path in (
        resource_path("CHANGELOG.md"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHANGELOG.md"),
    ):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as file:
                    return file.read()
            except OSError:
                continue
    return "No changelog is currently available."
