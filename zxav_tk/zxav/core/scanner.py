"""
Core scanning logic, independent of any GUI toolkit.
"""
import hashlib
import os
import time
import uuid
from urllib import error as urlerror

from . import vt_api
from .config import DETAILS_DIR, save_json_atomic


def sha256_of_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def format_bytes(size):
    if size is None:
        return "\u2014"
    try:
        size = float(size)
    except (TypeError, ValueError):
        return "\u2014"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return "\u2014"


class ScanCancelled(Exception):
    pass


class ScanEngine:
    """Wraps VirusTotal calls into rich scan results and persists per-scan
    engine detail to disk (kept out of the main history file, which stays
    small and fast to load)."""

    def __init__(self, api_key, cancel_event=None, status_callback=None):
        self.api_key = api_key
        self.cancel_event = cancel_event
        self.status_callback = status_callback or (lambda text: None)

    def _check_cancel(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCancelled("Scan cancelled.")

    def _poll_analysis(self, analysis_id, timeout=180):
        started = time.time()
        while True:
            self._check_cancel()
            if time.time() - started > timeout:
                raise TimeoutError("VirusTotal analysis timed out.")
            status, body = vt_api.vt_get_analysis(analysis_id, self.api_key)
            import json
            payload = json.loads(body.decode("utf-8"))
            attributes = payload.get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                return attributes
            self.status_callback(f"VirusTotal analysis: {attributes.get('status', 'queued')}")
            time.sleep(2)

    def _finalize(self, target, scan_type, size, attributes, permalink):
        malicious, suspicious, total_engines, engines = vt_api.extract_stats_and_engines(attributes)
        detections = malicious + suspicious
        result = "FLAGGED" if detections > 0 else "CLEAN"
        scan_id = uuid.uuid4().hex
        save_json_atomic(
            os.path.join(DETAILS_DIR, f"{scan_id}.json"),
            {"engines": engines, "permalink": permalink},
        )
        return {
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "size": size,
            "result": result,
            "detections": detections,
            "total_engines": total_engines,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": time.time(),
            "permalink": permalink,
        }

    def scan_file(self, path):
        self._check_cancel()
        size = os.path.getsize(path)
        self.status_callback(f"Hashing {os.path.basename(path)}...")
        file_hash = sha256_of_file(path)
        self._check_cancel()
        self.status_callback(f"Checking VirusTotal hash: {os.path.basename(path)}")
        permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
        try:
            status, body = vt_api.vt_lookup_file_hash(file_hash, self.api_key)
            if status == 200:
                import json
                payload = json.loads(body.decode("utf-8"))
                attributes = payload.get("data", {}).get("attributes", {})
                return self._finalize(path, "File", size, attributes, permalink)
        except urlerror.HTTPError as exc:
            if exc.code != 404:
                raise
        self.status_callback(f"Uploading {os.path.basename(path)} to VirusTotal...")
        analysis_id = vt_api.vt_upload_file(path, self.api_key)
        if not analysis_id:
            raise RuntimeError("VirusTotal did not return an analysis ID.")
        attributes = self._poll_analysis(analysis_id)
        return self._finalize(path, "File", size, attributes, permalink)

    def scan_url(self, target_url):
        self._check_cancel()
        self.status_callback(f"Submitting URL: {target_url}")
        analysis_id = vt_api.vt_submit_url(target_url, self.api_key)
        if not analysis_id:
            raise RuntimeError("VirusTotal did not return an analysis ID.")
        attributes = self._poll_analysis(analysis_id)
        permalink = f"https://www.virustotal.com/gui/url-id/{analysis_id}"
        return self._finalize(target_url, "URL", None, attributes, permalink)

    def iter_directory(self, directory):
        """Yields (index, total, path) then the caller scans each path.
        Kept separate from scanning so the UI can update progress without
        this class needing to know about threads/signals."""
        files = []
        for root, _dirs, filenames in os.walk(directory, followlinks=False):
            self._check_cancel()
            for filename in filenames:
                path = os.path.join(root, filename)
                if os.path.isfile(path):
                    files.append(path)
        total = len(files)
        for index, path in enumerate(files, start=1):
            self._check_cancel()
            yield index, total, path
