#!/usr/bin/env python3
"""Fail if the CL Cloudflare Radar TEST token appears in source or a build output.

The test/demo token lives only in the macOS Keychain of the testing machine
(service IbertConsulting.CL.CloudflareRadarTest, account radar-read-test). Shipping
builds must never contain it. This check reads the token from Keychain inside this
process, searches the given paths for its exact bytes (plain, UTF-16LE and base64
forms, and inside ZIP members), and prints only file names and PASS/FAIL - never
the token or any part of it.

Usage: python3 -I scripts/check-test-token-absent.py PATH [PATH ...]
Exit codes: 0 absent, 1 found, 2 token unavailable on this machine (check skipped).
For the self-test only, ATLAS_TOKEN_CHECK_FAKE supplies a fake value instead of Keychain.
"""
import base64
import os
import subprocess
import sys
import zipfile

SERVICE = "IbertConsulting.CL.CloudflareRadarTest"
ACCOUNT = "radar-read-test"
SKIP_DIRS = {".git", "target", "node_modules"}


def token():
    fake = os.environ.get("ATLAS_TOKEN_CHECK_FAKE")
    if fake:
        return fake.encode()
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"],
            capture_output=True, check=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.strip()
    return value if len(value) >= 20 else None


def needles(value):
    forms = [value, value.decode("ascii", "ignore").encode("utf-16-le")]
    # base64 of the token at each of the three byte alignments, minus padding-affected edges
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + value)[4:-4]
        if len(encoded) >= 16:
            forms.append(encoded)
    return forms


def scan_bytes(data, forms):
    return any(f in data for f in forms)


def scan_file(path, forms):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return [f"{path}: unreadable"]
    hits = [path] if scan_bytes(data, forms) else []
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if scan_bytes(archive.read(name), forms):
                        hits.append(f"{path}!{name}")
        except (zipfile.BadZipFile, OSError, RuntimeError):
            hits.append(f"{path}: unreadable zip")
    return hits


def main(paths):
    if not paths:
        print(__doc__.strip().splitlines()[-3])
        return 2
    value = token()
    if value is None:
        print("SKIP: test token not in this machine's Keychain; nothing to compare.")
        return 2
    forms = needles(value)
    hits, files = [], 0
    for root in paths:
        if os.path.isfile(root):
            files += 1
            hits += scan_file(root, forms)
            continue
        for directory, subdirs, names in os.walk(root):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for name in names:
                files += 1
                hits += scan_file(os.path.join(directory, name), forms)
    if hits:
        print("FAIL: test token found in:")
        for hit in hits:
            print("  " + hit)
        return 1
    print(f"PASS: test token absent from {files} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
