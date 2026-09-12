"""
Moves flagged files into a holding folder, stripping execute permission and
renaming them so they can't be double-clicked by accident, while keeping an
index so they can be restored to their original location later.
"""
import os
import shutil
import stat
import time
import uuid

from .config import QUARANTINE_DIR, QUARANTINE_INDEX_PATH, load_json, save_json_atomic


def _load_index():
    data = load_json(QUARANTINE_INDEX_PATH, [])
    return data if isinstance(data, list) else []


def _save_index(index):
    save_json_atomic(QUARANTINE_INDEX_PATH, index)


def list_items():
    return list(reversed(_load_index()))


def quarantine_file(original_path, sha256=None, detections=0):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    item_id = uuid.uuid4().hex
    quarantined_name = f"{item_id}.quarantine"
    quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)
    shutil.move(original_path, quarantined_path)
    try:
        os.chmod(quarantined_path, stat.S_IREAD)
    except OSError:
        pass
    entry = {
        "id": item_id,
        "original_path": original_path,
        "quarantined_path": quarantined_path,
        "sha256": sha256,
        "detections": detections,
        "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    index = _load_index()
    index.append(entry)
    _save_index(index)
    return entry


def restore_file(item_id, restore_path=None):
    index = _load_index()
    entry = next((item for item in index if item["id"] == item_id), None)
    if entry is None:
        raise KeyError("Quarantine item not found.")
    destination = restore_path or entry["original_path"]
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
    try:
        os.chmod(entry["quarantined_path"], stat.S_IREAD | stat.S_IWRITE)
    except OSError:
        pass
    shutil.move(entry["quarantined_path"], destination)
    index = [item for item in index if item["id"] != item_id]
    _save_index(index)
    return destination


def delete_permanently(item_id):
    index = _load_index()
    entry = next((item for item in index if item["id"] == item_id), None)
    if entry is None:
        raise KeyError("Quarantine item not found.")
    try:
        if os.path.exists(entry["quarantined_path"]):
            os.chmod(entry["quarantined_path"], stat.S_IREAD | stat.S_IWRITE)
            os.remove(entry["quarantined_path"])
    except OSError:
        pass
    index = [item for item in index if item["id"] != item_id]
    _save_index(index)
