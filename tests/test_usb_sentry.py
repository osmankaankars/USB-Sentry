import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from usb_sentry import USBSentry


def external_usb(volume_uuid, device_identifier="disk4s1"):
    return {
        "BusProtocol": "USB",
        "DeviceIdentifier": device_identifier,
        "Internal": False,
        "VolumeUUID": volume_uuid,
    }


class USBSentryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.volumes_dir = self.root / "Volumes"
        self.volumes_dir.mkdir()
        self.whitelist_file = self.root / "whitelist.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_sentry(self, devices=None):
        if devices is not None:
            self.whitelist_file.write_text(
                json.dumps({"authorized_devices": devices}), encoding="utf-8"
            )
        return USBSentry(
            whitelist_file=self.whitelist_file,
            volumes_dir=self.volumes_dir,
        )

    def test_loads_string_uuids_from_local_policy(self):
        sentry = self.make_sentry(["UUID-ONE", "UUID-TWO", "UUID-ONE"])

        self.assertEqual(sentry.authorized_uuids, {"UUID-ONE", "UUID-TWO"})

    def test_reads_diskutil_plist_metadata(self):
        sentry = self.make_sentry([])
        metadata = external_usb("TRUSTED-UUID")
        completed = mock.Mock(returncode=0, stdout=plistlib.dumps(metadata))

        with mock.patch("usb_sentry.subprocess.run", return_value=completed) as run:
            result = sentry._get_volume_metadata("Trusted Drive")

        self.assertEqual(result, metadata)
        run.assert_called_once_with(
            [
                "diskutil",
                "info",
                "-plist",
                str(self.volumes_dir / "Trusted Drive"),
            ],
            capture_output=True,
            check=False,
        )

    def test_missing_or_invalid_policy_fails_closed(self):
        missing = self.make_sentry()
        self.whitelist_file.write_text("not-json", encoding="utf-8")
        invalid_json = USBSentry(
            whitelist_file=self.whitelist_file,
            volumes_dir=self.volumes_dir,
        )
        self.whitelist_file.write_text(
            json.dumps({"authorized_devices": "UUID-ONE"}), encoding="utf-8"
        )
        invalid_shape = USBSentry(
            whitelist_file=self.whitelist_file,
            volumes_dir=self.volumes_dir,
        )

        self.assertEqual(missing.authorized_uuids, set())
        self.assertEqual(invalid_json.authorized_uuids, set())
        self.assertEqual(invalid_shape.authorized_uuids, set())

    def test_authorized_device_is_not_unmounted(self):
        sentry = self.make_sentry(["TRUSTED-UUID"])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                return_value=external_usb("TRUSTED-UUID"),
            ),
            mock.patch.object(sentry, "_unmount_device") as unmount,
        ):
            sentry._handle_new_device("Trusted Drive")

        unmount.assert_not_called()

    def test_unknown_and_unauthorized_devices_are_unmounted(self):
        sentry = self.make_sentry(["TRUSTED-UUID"])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                side_effect=[external_usb(None), external_usb("OTHER-UUID")],
            ),
            mock.patch.object(sentry, "_unmount_device") as unmount,
        ):
            sentry._handle_new_device("Unknown Drive")
            sentry._handle_new_device("Untrusted Drive")

        self.assertEqual(
            unmount.call_args_list,
            [mock.call("Unknown Drive"), mock.call("Untrusted Drive")],
        )

    def test_dot_prefixed_mount_is_still_evaluated(self):
        sentry = self.make_sentry([])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                return_value=external_usb(None),
            ) as get_metadata,
            mock.patch.object(sentry, "_unmount_device") as unmount,
        ):
            sentry._handle_new_device(".system-volume")

        get_metadata.assert_called_once_with(".system-volume")
        unmount.assert_called_once_with(".system-volume")

    def test_failed_unmount_is_retried_on_next_poll(self):
        sentry = self.make_sentry([])
        (self.volumes_dir / "Untrusted Drive").mkdir()
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                return_value=external_usb("OTHER-UUID"),
            ),
            mock.patch.object(
                sentry, "_unmount_device", side_effect=[False, True]
            ) as unmount,
        ):
            sentry.scan_once()
            self.assertNotIn("Untrusted Drive", sentry.known_volumes)
            sentry.scan_once()

        self.assertEqual(unmount.call_count, 2)
        self.assertIn("Untrusted Drive", sentry.known_volumes)

    def test_volume_present_at_startup_is_evaluated_on_first_poll(self):
        (self.volumes_dir / "Already Mounted").mkdir()
        sentry = self.make_sentry([])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                return_value=external_usb("OTHER-UUID"),
            ),
            mock.patch.object(sentry, "_unmount_device", return_value=True) as unmount,
        ):
            sentry.scan_once()

        unmount.assert_called_once_with("Already Mounted")

    def test_internal_and_non_usb_mounts_are_never_unmounted(self):
        sentry = self.make_sentry([])
        metadata = [
            {"BusProtocol": "PCI-Express", "Internal": True, "VolumeUUID": "SYSTEM"},
            {"BusProtocol": "Network", "Internal": False, "VolumeUUID": "SHARE"},
        ]
        with (
            mock.patch.object(
                sentry, "_get_volume_metadata", side_effect=metadata
            ) as get_metadata,
            mock.patch.object(sentry, "_unmount_device") as unmount,
        ):
            sentry._handle_new_device("Macintosh HD")
            sentry._handle_new_device("Network Share")

        self.assertEqual(get_metadata.call_count, 2)
        unmount.assert_not_called()

    def test_unclassified_mount_is_not_unmounted_and_is_marked_for_retry(self):
        sentry = self.make_sentry([])
        with (
            mock.patch.object(sentry, "_get_volume_metadata", return_value=None),
            mock.patch.object(sentry, "_unmount_device") as unmount,
        ):
            handled = sentry._handle_new_device("Unclassified")

        self.assertFalse(handled)
        unmount.assert_not_called()

    def test_transient_classification_failure_is_retried(self):
        (self.volumes_dir / "Late Metadata").mkdir()
        sentry = self.make_sentry([])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                side_effect=[None, external_usb("OTHER-UUID")],
            ),
            mock.patch.object(sentry, "_unmount_device", return_value=True) as unmount,
        ):
            sentry.scan_once()
            unmount.assert_not_called()
            self.assertNotIn("Late Metadata", sentry.known_volumes)
            sentry.scan_once()

        unmount.assert_called_once_with("Late Metadata")

    def test_same_name_replacement_is_re_evaluated(self):
        (self.volumes_dir / "Shared Label").mkdir()
        sentry = self.make_sentry(["TRUSTED-UUID"])
        with (
            mock.patch.object(
                sentry,
                "_get_volume_metadata",
                side_effect=[
                    external_usb("TRUSTED-UUID", "disk4s1"),
                    external_usb("OTHER-UUID", "disk5s1"),
                ],
            ),
            mock.patch.object(sentry, "_unmount_device", return_value=True) as unmount,
        ):
            sentry.scan_once()
            sentry.scan_once()

        unmount.assert_called_once_with("Shared Label")


if __name__ == "__main__":
    unittest.main()
