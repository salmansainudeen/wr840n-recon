#!/usr/bin/env python3
"""
wr840n_cve_check.py — PASSIVE CVE presence checker for a TP-Link TL-WR840N.

This does NOT exploit anything. It only:
  1. reads your router's firmware/hardware version (you supply it), and
  2. compares it against a table of known-vulnerable ranges.
Think of it as "am I theoretically in scope for this CVE?", not "can I pop it?".
"""

import re
import argparse
import urllib.request

# ---------------------------------------------------------------------------
# 1) The knowledge base: what we.
#    fw_max = the LAST firmware version that is vulnerable (inclusive).
#             None means "range y manually".
# ---------------------------------------------------------------------------
KNOWN_CVES = [
    {
        "id": "CVE-2018-11714",
        "desc": "Auth bypass / config download via broken session handling (EDB-44781)",
        "hw_revs": ["v6"],
        "fw_max": (4, 16),
    },
    {
        "id": "CVE-2019-15060",
        "desc": "OS command injection in traceroute function",
        "hw_revs": ["v6", "v5", "v4"],
        "fw_max": None,          # range not clearly published -> manual check
    },
    {
        "id": "CVE-2018-15172",
        "desc": "Buffer overflow via long Authorization HTTP header",
        "hw_revs": ["v6", "v5", "v4"],
        "fw_max": None,
    },
    {
        "id": "CVE-2021-46122",
        "desc": "Flaw in password-reset feature",
        "hw_revs": ["v6.20"],    # note: a DIFFERENT rev than plain v6
        "fw_max": None,
    },
    {
        "id": "CVE-2022-26639..26642",
        "desc": "Buffer overflows via DNSServers / minAddress / etc.",
        "hw_revs": ["v6.20"],
        "fw_max": None,
    },
]

# ---------------------------------------------------------------------------
# 2) Parse the two strings off the admin page into things we can compare.
# ---------------------------------------------------------------------------
def parse_firmware(fw_string):
    """'0.9.1 4.18 v0002.0 Build 231121 ...' -> ((4, 18), 231121)."""
    # The firmware version is the SECOND whitespace token, like '4.18'.
    ver_match = re.search(r"\b(\d+)\.(\d+)\b", fw_string.split()[1])
    version = (int(ver_match.group(1)), int(ver_match.group(2)))
    # The build date is the number after the word 'Build'.
    build_match = re.search(r"Build\s+(\d+)", fw_string)
    build = int(build_match.group(1)) if build_match else None
    return version, build

def parse_hardware(hw_string):
    """'TL-WR840N v6 00000007' -> 'v6'."""
    m = re.search(r"\b(v\d+(?:\.\d+)?)\b", hw_string)
    return m.group(1) if m else "unknown"

# ---------------------------------------------------------------------------
# 3) The comparator — the actual logic.
# ---------------------------------------------------------------------------
def assess(my_hw, my_fw_version):
    results = []
    for cve in KNOWN_CVES:
        if my_hw not in cve["hw_revs"]:
            verdict = "NOT APPLICABLE  (different hardware revision)"
        elif cve["fw_max"] is None:
            verdict = "VERIFY MANUALLY (affected range unclear)"
        elif my_fw_version <= cve["fw_max"]:
            verdict = "POTENTIALLY VULNERABLE (your firmware <= last vulnerable)"
        else:
            verdict = "LIKELY PATCHED (your firmware is newer)"
        results.append((cve["id"], verdict, cve["desc"]))
    return results

# ---------------------------------------------------------------------------
# 4) Optional: a SAFE fingerprint — just a HEAD request for the Server header.
#    No login, no payload. Purely informational.
# ---------------------------------------------------------------------------
def fingerprint(ip):
    try:
        req = urllib.request.Request(f"http://{ip}/")  # defaults to GET
        with urllib.request.urlopen(req, timeout=5) as resp:
            server = resp.headers.get("Server", "(none)")
            print(f"[*] {ip} HTTP Server header: {server}")
    except Exception as e:
        print(f"[!] Could not fingerprint {ip}: {e}")

# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Passive TL-WR840N CVE presence check")
    p.add_argument("--fw", default="0.9.1 4.18 v0002.0 Build 231121 Rel.2977n",
                   help="firmware version string from the admin page")
    p.add_argument("--hw", default="TL-WR840N v6 00000007",
                   help="hardware version string from the admin page")
    p.add_argument("--fingerprint", metavar="IP",
                   help="optional: safe HEAD request to read the Server header")
    args = p.parse_args()

    fw_version, build = parse_firmware(args.fw)
    hw_rev = parse_hardware(args.hw)

    print(f"[*] Hardware revision : {hw_rev}")
    print(f"[*] Firmware version  : {fw_version[0]}.{fw_version[1]}  (build {build})")
    print("-" * 70)

    for cve_id, verdict, desc in assess(hw_rev, fw_version):
        print(f"{cve_id:22} {verdict}")
        print(f"{'':22} └─ {desc}")

    if args.fingerprint:
        print("-" * 70)
        fingerprint(args.fingerprint)

    print("\n[note] 'POTENTIALLY VULNERABLE' and 'VERIFY MANUALLY' are hypotheses,")
    print("       not confirmations. Confirm against NVD/Exploit-DB before trusting.")

if __name__ == "__main__":
    main()
