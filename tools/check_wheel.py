"""Explicit installed wheel and tracked driver qualification; offline checks provision nothing."""

import argparse
import subprocess
import sys
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    "tools",
    "config",
    "evidence",
    "src",
    "tests",
    "docs",
    "compose.yaml",
    "spec.lock.json",
    "pyproject.toml",
    "uv.lock",
    "LICENSE",
    "README.md",
    ".python-version",
}
CHECKS = (
    ("architecture.py",),
    ("integration.py", "check"),
    ("workflow_assets.py", "check"),
    ("release_conformance.py", "check"),
    ("m0_acceptance.py", "--check"),
)
RUNNER = """import runpy, sys
wheel, script, *args = sys.argv[1:]
sys.path.insert(0, wheel)
sys.path.insert(0, str(__import__('pathlib').Path(script).parent))
import kryvola_platform
assert wheel in kryvola_platform.__file__
sys.argv = [script, *args]
runpy.run_path(script, run_name='__main__')
"""


def extract_driver(archive, root):
    with tarfile.open(archive) as tar:
        total = 0
        seen = set()
        for entry in tar:
            name = entry.name.rstrip("/")
            parts = name.split("/")
            if (
                name in seen
                or parts[0] not in INPUTS
                or any(p in {"", ".", ".."} for p in parts)
                or not (entry.isdir() or entry.isfile())
                or entry.size > 16 << 20
            ):
                raise ValueError("UNSAFE_DRIVER_ENTRY")
            seen.add(name)
            total += entry.size
            if total > 128 << 20:
                raise ValueError("DRIVER_LIMIT")
            path = root.joinpath(*parts)
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = tar.extractfile(entry)
                assert stream is not None
                path.write_bytes(stream.read())
        if not INPUTS <= {p.split("/")[0] for p in seen}:
            raise ValueError("INCOMPLETE_DRIVER")


def check(wheel, driver):
    wheel, driver = wheel.resolve(), driver.resolve()
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        extract_driver(driver, root)
        with ZipFile(wheel) as package:
            source = root / "src/kryvola_platform/_spec"
            expected = {
                p.relative_to(source).as_posix(): p.read_bytes()
                for p in source.rglob("*")
                if p.is_file()
            }
            actual = {
                name.removeprefix("kryvola_platform/_spec/"): package.read(name)
                for name in package.namelist()
                if name.startswith("kryvola_platform/_spec/") and not name.endswith("/")
            }
            if expected != actual or not expected:
                raise ValueError("WHEEL_RESOURCES_CHANGED")
        for script, *args in CHECKS:
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    RUNNER,
                    str(wheel),
                    str(root / "tools" / script),
                    *args,
                ],
                cwd=root,
                check=True,
                timeout=60,
            )
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); "
                "sys.argv=['kryvola_platform',sys.argv[1]]; "
                "runpy.run_module('kryvola_platform',run_name='__main__')",
                str(wheel),
                str(root / "config/foundation.json"),
            ],
            cwd=root,
            check=True,
            timeout=60,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    args = parser.parse_args()
    check(args.wheel, args.driver)
