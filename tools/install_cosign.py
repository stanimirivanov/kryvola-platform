"""Explicit CI tool setup. Runtime admission never installs or downloads tools."""

import hashlib
import platform
import urllib.request
from pathlib import Path

from kryvola_platform.release_set import COSIGN_DIGESTS, COSIGN_VERSION

system = platform.system()
if platform.machine().lower() not in {"amd64", "x86_64"} or system not in COSIGN_DIGESTS:
    raise RuntimeError("Unsupported Cosign tool platform")
name = "cosign-linux-amd64" if system == "Linux" else "cosign-windows-amd64.exe"
url = f"https://github.com/sigstore/cosign/releases/download/{COSIGN_VERSION}/{name}"
with urllib.request.urlopen(url, timeout=60) as response:
    data = response.read(268435457)
if len(data) > 268435456 or hashlib.sha256(data).hexdigest() != COSIGN_DIGESTS[system]:
    raise RuntimeError("Cosign tool digest mismatch")
root = Path(__file__).resolve().parents[1] / ".tools"
root.mkdir(exist_ok=True)
target = root / ("cosign.exe" if system == "Windows" else "cosign")
target.write_bytes(data)
target.chmod(0o700)
print(f"Installed checksum-verified Cosign {COSIGN_VERSION}")
