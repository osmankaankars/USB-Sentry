import json
import logging
import os
import plistlib
import subprocess
import time
from pathlib import Path

from termcolor import colored

# --- CONFIGURATION ---
WHITELIST_FILE = "whitelist.json"
LOG_FILE = "usb_security.log"
CHECK_INTERVAL = 2  # Seconds
VOLUMES_DIR = "/Volumes"
_UNSET = object()

logger = logging.getLogger("usb_sentry")


def configure_logging(log_file=LOG_FILE):
    """Configure the runtime file log without creating it during module import."""
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


class USBSentry:
    """
    Monitors macOS /Volumes directory for new mounts.
    Enforces a whitelist policy based on Volume UUIDs.
    """

    def __init__(self, whitelist_file=WHITELIST_FILE, volumes_dir=VOLUMES_DIR):
        self.whitelist_file = Path(whitelist_file)
        self.volumes_dir = Path(volumes_dir)
        self.authorized_uuids = self._load_whitelist()
        # The first poll must evaluate mounts that predate process startup.
        self.known_volumes = {}
        print(colored("[*] USB Sentry System Initialized...", "cyan"))
        print(
            colored(
                f"[*] Monitoring {self.volumes_dir} for activity (Policies: {len(self.authorized_uuids)} loaded)",
                "cyan",
            )
        )

    def _load_whitelist(self):
        """Loads allowed UUIDs from JSON config."""
        try:
            with self.whitelist_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(
                colored(
                    "[-] Whitelist file not found. Creating empty policy.", "yellow"
                )
            )
            return set()
        except (OSError, json.JSONDecodeError) as error:
            print(
                colored(
                    f"[-] Could not read whitelist: {error}. Using empty policy.",
                    "yellow",
                )
            )
            logger.warning(
                "Could not read whitelist %s: %s", self.whitelist_file, error
            )
            return set()

        devices = data.get("authorized_devices") if isinstance(data, dict) else None
        if not isinstance(devices, list) or any(
            not isinstance(device, str) for device in devices
        ):
            print(
                colored("[-] Invalid whitelist format. Using empty policy.", "yellow")
            )
            logger.warning("Invalid whitelist format in %s", self.whitelist_file)
            return set()

        return {device.strip() for device in devices if device.strip()}

    def _get_volume_metadata(self, mount_point):
        """Read trusted transport and identity metadata from diskutil's plist."""
        try:
            mount_path = self.volumes_dir / mount_point
            cmd = ["diskutil", "info", "-plist", str(mount_path)]
            result = subprocess.run(cmd, capture_output=True, check=False)

            if result.returncode != 0:
                logger.warning("diskutil info failed for %s", mount_path)
                return None

            metadata = plistlib.loads(result.stdout)
            return metadata if isinstance(metadata, dict) else None
        except (
            OSError,
            plistlib.InvalidFileException,
            subprocess.SubprocessError,
        ) as error:
            logger.error("Error retrieving metadata for %s: %s", mount_point, error)
            return None

    @staticmethod
    def _is_external_usb(metadata):
        """Limit enforcement to devices macOS identifies as external USB."""
        bus_protocol = str(metadata.get("BusProtocol", "")).strip().upper()
        return bus_protocol == "USB" and metadata.get("Internal") is False

    @staticmethod
    def _metadata_fingerprint(metadata):
        """Build a stable-enough identity to detect same-label replacements."""
        if metadata is None:
            return ("unclassified",)
        keys = (
            "BusProtocol",
            "DeviceIdentifier",
            "DiskUUID",
            "Internal",
            "MediaUUID",
            "ParentWholeDisk",
            "VolumeUUID",
        )
        return tuple(repr(metadata.get(key)) for key in keys)

    def _unmount_device(self, mount_point):
        """
        Forcefully unmounts a device using 'diskutil unmount'.
        """
        mount_path = self.volumes_dir / mount_point
        print(
            colored(
                f"[!] BLOCKING: Attempting to unmount {mount_path}...",
                "red",
                attrs=["bold"],
            )
        )
        cmd = ["diskutil", "unmount", "force", str(mount_path)]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            logger.warning("Unmounted unauthorized volume: %s", mount_point)
            return True

        logger.error("Failed to unmount unauthorized volume: %s", mount_point)
        return False

    def start_monitoring(self):
        """Main monitoring loop."""
        print(colored("[*] SENTINEL ACTIVE. Waiting for devices...", "green"))

        try:
            while True:
                self.scan_once()
                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n[*] Sentry shutting down...")

    def scan_once(self):
        """Evaluate one mount snapshot and retain failed unmounts for retry."""
        current_volumes = set(os.listdir(self.volumes_dir))
        next_known_volumes = {}
        retry_mounts = set()

        for volume in current_volumes:
            metadata = self._get_volume_metadata(volume)
            fingerprint = self._metadata_fingerprint(metadata)
            identity_changed = (
                volume not in self.known_volumes
                or self.known_volumes[volume] != fingerprint
            )
            if identity_changed and not self._handle_new_device(
                volume, metadata=metadata
            ):
                retry_mounts.add(volume)
                continue
            next_known_volumes[volume] = fingerprint

        removed_mounts = set(self.known_volumes) - current_volumes
        for volume in removed_mounts:
            print(colored(f"[-] Device Disconnected: {volume}", "grey"))

        self.known_volumes = next_known_volumes
        return retry_mounts

    def _handle_new_device(self, volume_name, metadata=_UNSET):
        """Process a newly detected volume."""
        print(colored(f"\n[+] NEW DEVICE DETECTED: {volume_name}", "yellow"))
        logger.info("Device connected: %s", volume_name)

        if metadata is _UNSET:
            metadata = self._get_volume_metadata(volume_name)
        if metadata is None:
            print(
                colored(
                    "   [?] Could not classify this mount. Leaving it unchanged.",
                    "yellow",
                )
            )
            logger.warning("Mount could not be classified: %s", volume_name)
            return False

        if not self._is_external_usb(metadata):
            print(colored("   [-] Not an external USB volume. Ignoring.", "grey"))
            logger.info("Ignored non-external-USB mount: %s", volume_name)
            return True

        uuid = metadata.get("VolumeUUID")

        if not isinstance(uuid, str) or not uuid.strip():
            print(
                colored(
                    "   [?] External USB has no usable UUID. Identifying as UNKNOWN.",
                    "red",
                )
            )
            return self._unmount_device(volume_name)

        uuid = uuid.strip()

        print(f"   > UUID: {uuid}")

        # Check Policy
        if uuid in self.authorized_uuids:
            print(colored("   [✓] ACCESS GRANTED: Device is whitelisted.", "green"))
            logger.info("Access granted: %s (%s)", volume_name, uuid)
            return True
        else:
            print(
                colored(
                    "   [X] UNAUTHORIZED DEVICE! Initiating defense protocol...",
                    "red",
                    attrs=["blink"],
                )
            )
            logger.warning("Unauthorized device: %s (%s)", volume_name, uuid)
            return self._unmount_device(volume_name)


if __name__ == "__main__":
    configure_logging()

    # Check for root privileges (Optional for unmount force but recommended)
    if os.geteuid() != 0:
        print(
            colored(
                "[!] Note: Running without root/sudo might restrict unmount capabilities.",
                "yellow",
            )
        )

    sentry = USBSentry()
    sentry.start_monitoring()
