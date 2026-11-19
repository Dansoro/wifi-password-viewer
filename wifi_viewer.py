#!/usr/bin/env python3
"""
Wi-Fi Password Viewer
=====================

A small defensive / educational utility that lists the Wi-Fi profiles
Windows has already saved on the local machine and shows their stored
pre-shared keys.

It does NOT crack, capture, or transmit anything. It only reads what
Windows already stores locally, and only for the machine it runs on.
Revealing all-user keys requires Administrator rights.

How it works
------------
Instead of scraping the localized text output of `netsh wlan show profile`
(which breaks on non-English Windows and mangles Unicode SSIDs), this tool
exports each profile to XML with `netsh wlan export profile key=clear` and
reads the stable, non-localized XML tags (`name`, `authentication`,
`keyMaterial`, `protected`). That makes it language-independent and
Unicode-safe, and it lets the tool tell the difference between an open
network, an enterprise (802.1X) profile with no stored key, and a
DPAPI-encrypted key that needs elevation to reveal.

Usage
-----
    python wifi_viewer.py                 # pretty table (default)
    python wifi_viewer.py -f csv -o out.csv
    python wifi_viewer.py -f json
    python wifi_viewer.py --no-banner

Author : Cyber_Warrior
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass

__version__ = "1.0.0"

# DPAPI provider signature; key material beginning with this is ciphertext.
_DPAPI_SIGNATURE = "01000000D08C9DDF0115D1118C7A00C04FC297EB"


@dataclass
class Profile:
    """A single saved Wi-Fi profile."""

    ssid: str
    authentication: str
    status: str  # "open" | "psk" | "enterprise" | "encrypted" | "unknown"
    key: str | None

    def display_key(self) -> str:
        """Human-readable value for the key/status column."""
        labels = {
            "open": "Open network / no password",
            "enterprise": f"No stored key ({self.authentication} — 802.1X)",
            "encrypted": "Key encrypted (DPAPI) — run as Administrator",
            "unknown": "No key available (run as Administrator?)",
        }
        if self.status == "psk" and self.key:
            return self.key
        return labels.get(self.status, "Unknown")


# --------------------------------------------------------------------------- #
# Environment helpers
# --------------------------------------------------------------------------- #
def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    """True if the process is running elevated."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _netsh_path() -> str:
    system32 = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netsh.exe"
    )
    return system32 if os.path.exists(system32) else "netsh"


def _run_netsh(args: list[str]) -> str | None:
    """Run netsh; return stdout, or None if netsh is unavailable."""
    try:
        result = subprocess.run(
            [_netsh_path(), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except FileNotFoundError:
        return None


# --------------------------------------------------------------------------- #
# XML parsing
# --------------------------------------------------------------------------- #
def _local_tag(element: ET.Element) -> str:
    """Tag name without its XML namespace, e.g. '{...}name' -> 'name'."""
    return element.tag.rsplit("}", 1)[-1]


def _find_text(root: ET.Element, tag: str) -> str | None:
    """First element with the given local tag name, namespace-agnostic."""
    for el in root.iter():
        if _local_tag(el) == tag:
            return (el.text or "").strip()
    return None


def _parse_profile(path: str) -> Profile | None:
    """Parse one exported profile XML file into a Profile."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None

    ssid = _find_text(root, "name") or "<unknown>"
    auth = (_find_text(root, "authentication") or "").strip()
    auth_l = auth.lower()
    protected = (_find_text(root, "protected") or "").lower()
    key = _find_text(root, "keyMaterial")

    encrypted = bool(key) and (
        protected == "true" or key.upper().startswith(_DPAPI_SIGNATURE)
    )

    if key and not encrypted:
        status = "psk"
    elif encrypted:
        status, key = "encrypted", None
    elif auth_l == "open":
        status = "open"
    elif auth_l:
        status = "enterprise"
    else:
        status = "unknown"

    return Profile(ssid=ssid, authentication=auth or "unknown", status=status, key=key)


def get_profiles() -> list[Profile]:
    """Export and parse every saved Wi-Fi profile on this machine."""
    with tempfile.TemporaryDirectory() as tmp:
        if _run_netsh(["wlan", "export", "profile", "key=clear", f"folder={tmp}"]) is None:
            raise RuntimeError("Could not run netsh. Is this Windows with Wi-Fi?")

        profiles = []
        for name in sorted(os.listdir(tmp)):
            if name.lower().endswith(".xml"):
                parsed = _parse_profile(os.path.join(tmp, name))
                if parsed:
                    profiles.append(parsed)
        return profiles


# --------------------------------------------------------------------------- #
# Output formatting
# --------------------------------------------------------------------------- #
def format_table(profiles: list[Profile]) -> str:
    width = max((len(p.ssid) for p in profiles), default=10) + 4
    width = min(max(width, 20), 45)
    lines = [
        f"{'Wi-Fi Name':<{width}}Password / Status",
        "-" * (width + 40),
    ]
    for p in profiles:
        lines.append(f"{p.ssid:<{width}}{p.display_key()}")
    lines.append("-" * (width + 40))
    lines.append(f"Total networks found: {len(profiles)}")
    return "\n".join(lines)


def format_csv(profiles: list[Profile]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ssid", "authentication", "status", "key"])
    for p in profiles:
        writer.writerow([p.ssid, p.authentication, p.status, p.key or ""])
    return buf.getvalue()


def format_json(profiles: list[Profile]) -> str:
    return json.dumps([asdict(p) for p in profiles], indent=2, ensure_ascii=False)


_FORMATTERS = {"table": format_table, "csv": format_csv, "json": format_json}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
BANNER = r"""
======================================================================
      ___
     / _ | ___  ___  ___  __ __  __ _
    / __ |/ _ \/ _ \/ _ \/ // / /  ' \
   /_/ |_/_//_/\___/_//_/\_, / /_/_/_/
                        /___/
                 Wi-Fi Password Viewer
======================================================================
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List saved Wi-Fi profiles and their stored keys (local machine only).",
        epilog="For authorized use on systems you own or administer.",
    )
    parser.add_argument(
        "-f", "--format", choices=_FORMATTERS, default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--no-banner", action="store_true", help="Suppress the banner."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if not is_windows():
        print("[!] This tool only runs on Windows.", file=sys.stderr)
        return 1

    # Banner goes to stderr so piped table/csv/json output stays clean.
    if not args.no_banner and args.format == "table" and not args.output:
        print(BANNER)
    if not is_admin():
        print("[*] Not running as Administrator — some keys may be hidden.\n",
              file=sys.stderr)

    try:
        profiles = get_profiles()
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if not profiles:
        print("No saved Wi-Fi profiles were found.", file=sys.stderr)
        return 0

    rendered = _FORMATTERS[args.format](profiles)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(rendered)
        print(f"[+] Wrote {len(profiles)} profiles to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
