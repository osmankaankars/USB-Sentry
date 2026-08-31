# USB Sentry

> A macOS proof of concept that classifies mounted volumes, checks external USB storage against a local UUID allowlist, and attempts to unmount unauthorized devices.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)
![CI](https://github.com/osmankaankars/USB-Sentry/actions/workflows/ci.yml/badge.svg)

## What it demonstrates

- Polling `/Volumes` and re-evaluating mounts whose `diskutil` identity changes.
- Reading transport, internal/external status, device identity, and volume UUID from `diskutil info -plist`.
- Limiting enforcement to volumes macOS reports as external USB devices; internal, network, and other transports are left unchanged.
- A fail-closed local allowlist for classified external USB devices: missing, malformed, and unknown UUIDs are not authorized.
- An attempted `diskutil unmount force` response for unauthorized volumes.
- Retry on the next polling cycle when an unmount attempt fails.
- Local event logging for review.

The tracked `whitelist.example.json` contains placeholders only. The active `whitelist.json` and runtime log are deliberately ignored so device identifiers and workstation activity are not committed.

## Requirements

- macOS with `diskutil`
- Python 3.11+
- Permission to inspect and unmount the target volumes

## Setup

```bash
git clone https://github.com/osmankaankars/USB-Sentry.git
cd USB-Sentry
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp whitelist.example.json whitelist.json
```

Replace the placeholder in `whitelist.json` with a trusted volume UUID:

```json
{
    "authorized_devices": [
        "YOUR-TRUSTED-VOLUME-UUID"
    ]
}
```

Find a mounted volume's UUID with:

```bash
diskutil info "/Volumes/YOUR_VOLUME_NAME" | grep "Volume UUID"
```

## Run

```bash
sudo python usb_sentry.py
```

The process checks mount metadata every two seconds. Existing external USB volumes are evaluated on the first cycle, same-label replacements are re-evaluated when their identity changes, and failed classification or unmount operations are retried. Events are written to the ignored `usb_security.log` file; review it because an unmount attempt can still fail.

## Tests

```bash
python -m unittest discover -s tests -v
```

The portable unit tests use temporary mount directories and mocked `diskutil` boundaries; they do not unmount real devices. GitHub Actions runs the same suite on Python 3.11.

## Security and operational limits

USB Sentry is a learning PoC, not a full DLP or endpoint-protection product.

- macOS mounts a volume before this polling process observes it. This tool cannot guarantee prevention of reads or writes during that interval.
- `/Volumes` can contain system, disk-image, and network mounts. The prototype acts only when `diskutil` reports `BusProtocol=USB` and `Internal=false`; if those fields are missing or metadata cannot be read, it leaves the mount unchanged and retries classification.
- Classification depends on macOS-provided metadata and has not been validated across every enclosure, hub, filesystem, or macOS release.
- A volume UUID is an identifier, not strong device authentication, and should not be treated as tamper-proof.
- Force-unmount can disrupt legitimate work and can fail because of permissions or open files. Test only on systems and media you control.
- The process has no centralized policy distribution, tamper protection, health monitoring, or guaranteed log delivery.
- For managed environments, prefer OS-supported device-control/MDM controls and use this project only as a lab demonstration.

## Author

Osman Kaan Kars — Senior Cybersecurity Engineer at SchutzOn
