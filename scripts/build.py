#!/usr/bin/env python3
"""One-shot build script (zero third-party dependencies).

Produces ``dist/hexscope.pyz`` — a single-file, executable zipapp that runs on
any machine with Python 3.8+::

    ./dist/hexscope.pyz stats firmware.bin

It optionally builds a wheel/sdist when the ``build`` module is available; a
missing ``build`` never fails the run (the zipapp is the primary artefact).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipapp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = "hexscope"
DIST = os.path.join(ROOT, "dist")


def _read_version() -> str:
    namespace: dict = {}
    init_path = os.path.join(ROOT, PACKAGE, "__init__.py")
    with open(init_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("__version__"):
                exec(line, namespace)  # noqa: S102 - trusted local file
                break
    return namespace.get("__version__", "0.0.0")


def run_tests() -> bool:
    """Run the unittest suite; return ``True`` on success."""
    print("▶ running tests")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT,
    )
    return result.returncode == 0


def build_zipapp(version: str) -> str:
    """Create the single-file executable archive."""
    print("▶ building zipapp")
    os.makedirs(DIST, exist_ok=True)
    target = os.path.join(DIST, "hexscope.pyz")
    if os.path.exists(target):
        os.remove(target)
    with tempfile.TemporaryDirectory() as tmp:
        stage = os.path.join(tmp, "stage")
        shutil.copytree(os.path.join(ROOT, PACKAGE), os.path.join(stage, PACKAGE))
        # Drop caches that may have been copied along.
        for leftover in os.listdir(os.path.join(stage, PACKAGE)):
            if leftover == "__pycache__":
                shutil.rmtree(os.path.join(stage, PACKAGE, leftover), ignore_errors=True)
        zipapp.create_archive(
            stage,
            target,
            interpreter="/usr/bin/env python3",
            main=f"{PACKAGE}.__main__:main",
            compressed=True,
        )
    os.chmod(target, 0o755)
    size = os.path.getsize(target)
    print(f"  ✔ {target} ({size} bytes)")
    return target


def build_distributions() -> None:
    """Build sdist/wheel when ``build`` is installed (best effort)."""
    try:
        import build  # noqa: F401
    except ImportError:
        print("  ⚠ skipping sdist/wheel (install `pip install build` to enable)")
        return
    print("▶ building sdist/wheel")
    result = subprocess.run([sys.executable, "-m", "build"], cwd=ROOT)
    if result.returncode != 0:
        print("  ⚠ sdist/wheel build failed (zipapp is still available)")


def smoke_test(archive: str) -> bool:
    """Run the packaged CLI once to prove the archive is functional."""
    print("▶ smoke test")
    result = subprocess.run([sys.executable, archive, "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ✘ {result.stderr.strip()}")
        return False
    print(f"  ✔ {result.stdout.strip()}")
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build HexScope artefacts.")
    parser.add_argument("--skip-tests", action="store_true", help="do not run the test suite")
    parser.add_argument("--no-dist", action="store_true", help="zipapp only")
    args = parser.parse_args(argv)

    version = _read_version()
    print(f"HexScope {version} — build started")

    if not args.skip_tests and not run_tests():
        print("✘ tests failed, aborting build")
        return 1

    archive = build_zipapp(version)
    if not smoke_test(archive):
        return 1

    if not args.no_dist:
        build_distributions()

    print("✔ build complete — artefacts in dist/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
