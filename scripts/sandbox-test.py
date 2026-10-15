#!/usr/bin/env python3
"""Verify real kernel restrictions in a disposable child process."""
import argparse
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", default="target/debug/examples/sandbox-probe")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="kerbin-sandbox-") as directory:
    secret = pathlib.Path(directory) / "secret"
    forbidden = pathlib.Path(directory) / "forbidden"
    secret.write_text("Must not be readable after confinement.")
    result = subprocess.run([str(pathlib.Path(args.binary).resolve()), str(secret), str(forbidden)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("PASS:"), result.stdout + result.stderr
    assert not forbidden.exists(), "Sandboxed process created a forbidden file"
    print(result.stdout, end="")
