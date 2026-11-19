# Wi-Fi Password Viewer

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small command-line utility that lists the Wi-Fi profiles Windows has
already saved on the **local machine** and shows their stored pre-shared
keys. It is intended as a defensive and educational tool — for recovering
your own forgotten keys, auditing which networks a machine has joined, and
demonstrating why saved Wi-Fi credentials are a credential-harvesting
target.

It does **not** crack, intercept, or transmit anything. It only reads what
Windows has already stored locally.

---

## ⚠️ Authorized use only

This tool reads credentials from the machine it runs on. Run it **only on
systems you own or are explicitly authorized to administer.** Using it to
extract credentials from a machine you do not have permission to access may
be illegal in your jurisdiction. The author assumes no liability for misuse.

---

## Features

- **Language-independent.** Reads exported XML rather than scraping
  localized `netsh` text, so it works on any Windows display language.
- **Unicode-safe.** SSIDs with non-ASCII characters are preserved correctly.
- **Honest status labels.** Distinguishes open networks, enterprise (802.1X)
  profiles with no stored key, and DPAPI-encrypted keys that need elevation.
- **Multiple output formats:** pretty table, CSV, or JSON.
- **No third-party dependencies** — standard library only.

## Requirements

- Windows
- Python 3.8 or newer
- Administrator rights to reveal **all-user** profile keys

## Installation

```bash
git clone https://github.com/Dansoro/wifi-password-viewer.git
cd wifi-password-viewer
```

No packages to install — it uses the Python standard library only.

## Usage

```bash
# Pretty table (default)
python wifi_viewer.py

# Export to CSV
python wifi_viewer.py -f csv -o networks.csv

# JSON to stdout
python wifi_viewer.py -f json

# Suppress the banner
python wifi_viewer.py --no-banner
```

For complete results, run from an **elevated** terminal
(right-click → *Run as administrator*).

### Example

```
Wi-Fi Name                     Password / Status
-----------------------------------------------------------
HOME_WIFI                      correcthorsebattery
OfficeGuest                    Open network / no password
CorpSecure                     No stored key (WPA2 — 802.1X)
LegacyAP                       Key encrypted (DPAPI) — run as Administrator
-----------------------------------------------------------
Total networks found: 4
```

## How it works

Windows stores each saved network as a profile managed by `netsh`. Rather
than parse the localized human-readable output of `netsh wlan show profile`,
this tool runs:

```
netsh wlan export profile key=clear folder=<temp>
```

which writes one XML file per profile into a temporary directory. XML tags
(`name`, `authentication`, `keyMaterial`, `protected`) are **not** translated
and are properly encoded, which is why this approach is language-independent
and Unicode-safe. The temporary files are deleted automatically when the
program exits.

A key stored with `<protected>true</protected>`, or whose material begins
with the DPAPI provider signature `01000000D08C9DDF…`, is ciphertext rather
than a password; the tool labels these instead of printing the blob.

## For defenders (blue team)

The same `netsh wlan ... key=clear` technique this tool uses is a common
credential-harvesting step in infostealers and post-exploitation scripts.
Worth hunting for:

- **Sysmon Event ID 1** / **Security Event ID 4688** (with command-line
  auditing) where `netsh.exe` runs with `wlan` and `key=clear`.
- The **export** variant additionally drops `.xml` files to disk — pair the
  process signal with **Sysmon Event ID 11** (file create) for `*.xml` in a
  temp path to reduce false positives.
- A burst of `netsh wlan show profile` / `export profile` calls from a
  scripting host (`python.exe`, `powershell.exe`) with an unusual parent.

Example PowerShell hunt:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'netsh' -and $_.Message -match 'key=clear' }
```

**Mitigations:** prefer enterprise (802.1X) Wi-Fi over shared PSKs so no
reusable key is stored on endpoints; restrict local administrator rights;
and remove stale profiles with `netsh wlan delete profile name="<SSID>"`.

## License

Released under the [MIT License](LICENSE).
