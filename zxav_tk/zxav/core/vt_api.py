"""
Thin VirusTotal v3 API client built on urllib (no extra HTTP dependency).
"""
import json
import os
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlencode

from .config import VT_BASE


def vt_headers(api_key):
    return {"x-apikey": api_key, "Accept": "application/json"}


def vt_request(url, api_key, method="GET", data=None, headers=None):
    request_headers = vt_headers(api_key)
    if headers:
        request_headers.update(headers)
    req = urlrequest.Request(url, data=data, headers=request_headers, method=method)
    with urlrequest.urlopen(req, timeout=60) as response:
        return response.status, response.read()


def vt_verify_key(api_key):
    status, _ = vt_request(f"{VT_BASE}/users/me", api_key)
    return 200 <= status < 300


def vt_lookup_file_hash(file_hash, api_key):
    return vt_request(f"{VT_BASE}/files/{file_hash}", api_key)


def vt_get_upload_url(api_key):
    status, body = vt_request(f"{VT_BASE}/files/upload_url", api_key)
    if not 200 <= status < 300:
        raise RuntimeError("VirusTotal could not provide an upload URL.")
    payload = json.loads(body.decode("utf-8"))
    upload_url = payload.get("data") if isinstance(payload, dict) else None
    if not upload_url:
        raise RuntimeError("VirusTotal returned an invalid upload URL.")
    return upload_url


def vt_upload_file(path, api_key):
    file_size = os.path.getsize(path)
    upload_url = vt_get_upload_url(api_key) if file_size > 32 * 1024 * 1024 else f"{VT_BASE}/files"
    boundary = "----ZXAVBoundary7MA4YWxkTrZu0gW"
    filename = os.path.basename(path)
    with open(path, "rb") as file:
        file_data = file.read()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status, body = vt_request(upload_url, api_key, method="POST", data=body, headers=headers)
    if not 200 <= status < 300:
        raise RuntimeError(f"VirusTotal upload failed with HTTP {status}.")
    payload = json.loads(body.decode("utf-8"))
    return payload.get("data", {}).get("id") if isinstance(payload, dict) else None


def vt_submit_url(target_url, api_key):
    data = urlencode({"url": target_url}).encode("utf-8")
    status, body = vt_request(
        f"{VT_BASE}/urls",
        api_key,
        method="POST",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if not 200 <= status < 300:
        raise RuntimeError(f"VirusTotal URL submission failed with HTTP {status}.")
    payload = json.loads(body.decode("utf-8"))
    return payload.get("data", {}).get("id") if isinstance(payload, dict) else None


def vt_get_analysis(analysis_id, api_key):
    return vt_request(f"{VT_BASE}/analyses/{analysis_id}", api_key)


def extract_stats_and_engines(attributes):
    """
    Normalizes the two shapes VT returns engine data in:
    - cached file lookups: last_analysis_stats / last_analysis_results
    - fresh analyses:      stats / results
    Returns (malicious, suspicious, total_engines, engines_dict).
    """
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    results = attributes.get("last_analysis_results") or attributes.get("results") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total_engines = sum(int(v or 0) for v in stats.values()) if stats else len(results)
    engines = {}
    for engine_name, engine_data in (results or {}).items():
        if not isinstance(engine_data, dict):
            continue
        engines[engine_name] = {
            "category": engine_data.get("category", "undetected"),
            "result": engine_data.get("result"),
            "engine_version": engine_data.get("engine_version"),
        }
    return malicious, suspicious, total_engines, engines
