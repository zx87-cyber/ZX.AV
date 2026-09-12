"""
License key validation, expiry computation, and display formatting.
"""
import time
from datetime import datetime

from .config import TIER_DURATIONS


def validate_license(key, license_keys):
    key = (key or "").strip().upper()
    if not key:
        return None
    tier = license_keys.get(key)
    if tier is None:
        return None
    tier = str(tier).upper()
    if tier not in TIER_DURATIONS:
        return None
    return tier


def compute_expiry(tier, activated_at):
    duration = TIER_DURATIONS.get(tier)
    if duration is None:
        return None
    return activated_at + duration


def license_is_expired(config):
    tier = config.get("license_tier")
    expiry = config.get("license_expiry")
    if not tier:
        return True
    if tier == "LIFETIME":
        return False
    if expiry is None:
        return True
    try:
        return time.time() >= float(expiry)
    except (TypeError, ValueError):
        return True


def format_expiry(config):
    tier = config.get("license_tier")
    if not tier:
        return "No license"
    if tier == "LIFETIME":
        return "Never expires"
    expiry = config.get("license_expiry")
    if expiry is None:
        return "Unknown"
    try:
        remaining = max(0, float(expiry) - time.time())
    except (TypeError, ValueError):
        return "Unknown"
    if remaining < 60:
        return f"{int(remaining)}s remaining"
    if remaining < 3600:
        return f"{int(remaining // 60)}m {int(remaining % 60)}s remaining"
    if remaining < 86400:
        return f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m remaining"
    days = int(remaining // 86400)
    try:
        date_text = datetime.fromtimestamp(float(expiry)).strftime("%d %b %Y")
    except (ValueError, OSError):
        date_text = "unknown date"
    return f"{days}d remaining \u2022 expires {date_text}"


def clear_license(config):
    for field in ("license_key", "license_tier", "license_activated", "license_expiry"):
        config.pop(field, None)
