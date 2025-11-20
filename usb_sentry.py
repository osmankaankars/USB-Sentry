import os
import time
import json
import subprocess
import logging
from datetime import datetime
from termcolor import colored

# --- CONFIGURATION ---
WHITELIST_FILE = "whitelist.json"
LOG_FILE = "usb_security.log"
CHECK_INTERVAL = 2  # Seconds

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class USBSentry:
    """
    Monitors macOS /Volumes directory for new mounts.
    Enforces a whitelist policy based on Volume UUIDs.
    """
    
    def __init__(self):
        self.authorized_uuids = self._load_whitelist()
        self.known_volumes = set(os.listdir("/Volumes"))
        print(colored("[*] USB Sentry System Initialized...", "cyan"))
        print(colored(f"[*] Monitoring /Volumes for activity (Policies: {len(self.authorized_uuids)} loaded)", "cyan"))

    def _load_whitelist(self):
        """Loads allowed UUIDs from JSON config."""
        try:
            with open(WHITELIST_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get("authorized_devices", []))
        except FileNotFoundError:
            print(colored("[-] Whitelist file not found. Creating empty policy.", "yellow"))
            return set()

    def _get_volume_uuid(self, mount_point):
        """
        Uses 'diskutil info' to retrieve the unique UUID of a mounted volume.
        """
        try:
            # Execute macOS native disk utility
            cmd = ["diskutil", "info", f"/Volumes/{mount_point}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse output for 'Volume UUID'
            for line in result.stdout.split('\n'):
                if "Volume UUID" in line:
                    # Line format: "   Volume UUID:               ABC-123..."
                    return line.split(':')[-1].strip()
            return None
        except Exception as e:
            logging.error(f"Error retrieving UUID for {mount_point}: {str(e)}")
            return None

    def _unmount_device(self, mount_point):
        """
        Forcefully unmounts a device using 'diskutil unmount'.
        """
        print(colored(f"[!] BLOCKING: Attempting to unmount /Volumes/{mount_point}...", "red", attrs=['bold']))
        cmd = ["diskutil", "unmount", "force", f"/Volumes/{mount_point}"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.warning(f"Blocked and Unmounted: {mount_point}")

    def start_monitoring(self):
        """Main monitoring loop."""
        print(colored("[*] SENTINEL ACTIVE. Waiting for devices...", "green"))
        
        try:
            while True:
                current_volumes = set(os.listdir("/Volumes"))
                
                # Detect New Connections
                new_mounts = current_volumes - self.known_volumes
                
                for volume in new_mounts:
                    self._handle_new_device(volume)

                # Detect Removals
                removed_mounts = self.known_volumes - current_volumes
                for volume in removed_mounts:
                    print(colored(f"[-] Device Disconnected: {volume}", "grey"))
                
                # Update state
                self.known_volumes = current_volumes
                time.sleep(CHECK_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n[*] Sentry shutting down...")

    def _handle_new_device(self, volume_name):
        """Process a newly detected volume."""
        # Ignore hidden system files/volumes if any
        if volume_name.startswith('.'): 
            return

        print(colored(f"\n[+] NEW DEVICE DETECTED: {volume_name}", "yellow"))
        logging.info(f"Device Connected: {volume_name}")
        
        # Get Unique ID
        uuid = self._get_volume_uuid(volume_name)
        
        if not uuid:
            print(colored(f"   [?] Could not retrieve UUID. Identifying as UNKNOWN.", "red"))
            # Policy decision: Block unknown? For demo, we assume block.
            self._unmount_device(volume_name)
            return

        print(f"   > UUID: {uuid}")
        
        # Check Policy
        if uuid in self.authorized_uuids:
            print(colored("   [✓] ACCESS GRANTED: Device is whitelisted.", "green"))
            logging.info(f"Access Granted: {volume_name} ({uuid})")
        else:
            print(colored("   [X] UNAUTHORIZED DEVICE! Initiating defense protocol...", "red", attrs=['blink']))
            logging.warning(f"Unauthorized Access Attempt: {volume_name} ({uuid})")
            self._unmount_device(volume_name)

if __name__ == "__main__":
    # Check for root privileges (Optional for unmount force but recommended)
    if os.geteuid() != 0:
        print(colored("[!] Note: Running without root/sudo might restrict unmount capabilities.", "yellow"))
    
    sentry = USBSentry()
    sentry.start_monitoring()
