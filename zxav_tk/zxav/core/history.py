"""
Persistent scan history, capped at MAX_HISTORY entries.
"""
import os

from .config import DETAILS_DIR, HISTORY_PATH, MAX_HISTORY, load_json, save_json_atomic


def load_history():
    data = load_json(HISTORY_PATH, [])
    return data[-MAX_HISTORY:] if isinstance(data, list) else []


def save_history(history):
    save_json_atomic(HISTORY_PATH, history[-MAX_HISTORY:])


def load_detail(scan_id):
    return load_json(os.path.join(DETAILS_DIR, f"{scan_id}.json"), {"engines": {}, "permalink": None})


def compute_stats(history):
    total = len(history)
    clean = sum(1 for e in history if e.get("result") == "CLEAN")
    flagged = sum(1 for e in history if e.get("result") == "FLAGGED")
    errors = sum(1 for e in history if e.get("result") == "ERROR")
    last = history[-1].get("result", "\u2014") if history else "\u2014"
    return {"total": total, "clean": clean, "flagged": flagged, "errors": errors, "last": last}
