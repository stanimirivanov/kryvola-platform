"""Exact Debian Secret Service helper closure for the disposable owner domain."""

import hashlib
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/m1-owner-packages.lock.json"
CACHE = ROOT / "build/m1-owner-session-debs"


def stage(destination, *, entries=None, cache=CACHE):
    if entries is None:
        locked = json.loads(LOCK.read_bytes())
        if (
            locked["schema_version"] != "m1-owner-packages-v1"
            or locked["base_image"]
            != json.loads((ROOT / "config/m1.lock.json").read_bytes())["services"]["python"]
        ):
            raise ValueError("M1_OWNER_PACKAGE_LOCK")
        entries = locked["packages"]
    if not 1 <= len(entries) <= 64:
        raise ValueError("M1_OWNER_PACKAGE_LOCK")
    cache.mkdir(parents=True, exist_ok=True)
    verified = []
    for entry in entries:
        name, url = entry["name"], entry["url"]
        if (
            not re.fullmatch(r"[a-zA-Z0-9_.+%~-]+\.deb", name)
            or not url.startswith("https://deb.debian.org/debian/pool/")
            or not re.fullmatch("[0-9a-f]{64}", entry["sha256"])
            or not 0 < entry["bytes"] <= 16 << 20
        ):
            raise ValueError("M1_OWNER_PACKAGE_LOCK")
        path = cache / name
        if path.is_symlink():
            raise ValueError("M1_OWNER_PACKAGE_CHANGED")
        if not path.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(entry["bytes"] + 1)
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("M1_OWNER_PACKAGE_CHANGED")
            with path.open("xb") as stream:
                stream.write(data)
        with path.open("rb") as stream:
            data = stream.read(entry["bytes"] + 1)
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("M1_OWNER_PACKAGE_CHANGED")
        verified.append((name, data))
    # Nothing enters a Docker context before the complete closure verifies.
    destination.mkdir()
    for name, data in verified:
        (destination / name).write_bytes(data)
