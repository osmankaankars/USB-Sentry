# USB Sentry 🛡️

> **An automated Endpoint Security tool for macOS that detects, logs, and actively blocks unauthorized USB storage devices.**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)
![Security](https://img.shields.io/badge/Focus-DLP_&_Endpoint_Protection-red)

---

## 📖 Overview
In secure environments, unauthorized external storage devices pose a significant risk for **Data Exfiltration** and **Malware Injection**.

**USB Sentry** acts as a lightweight DLP (Data Loss Prevention) agent. It monitors the system for mount events in real-time, validates the device identifier (UUID) against a secure whitelist, and automatically ejects (unmounts) any unauthorized device before data transfer can occur.

---

## ✨ Features
* **Real-Time Monitoring:** Detects new storage devices immediately upon insertion.
* **UUID-Based Authentication:** Identifies devices by their unique hardware UUID (Volume ID), not just by name.
* **Active Response:** Automatically executes `diskutil unmount force` on unauthorized devices.
* **Security Logging:** Maintains a detailed audit log (`usb_security.log`) of all connection attempts for forensic review.

---

## ⚙️ Installation

### Prerequisites
* macOS (Tested on Sonoma/Ventura)
* Python 3.8+

### Setup
1. Clone the repository:
```bash
git clone https://github.com/osmankaankars/USB-Sentry.git
cd USB-Sentry
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. **Configure Policy:**

Edit `whitelist.json` to add the UUIDs of allowed devices:

```json
{
    "authorized_devices": [
        "E5C8-4F2A",
        "YOUR-TRUSTED-UUID-HERE"
    ]
}
```

---

## 🚀 Usage

Run the sentry agent (sudo recommended for forceful unmounting privileges):

```bash
sudo python usb_sentry.py
```

---

## 🔍 How to find your UUID?

To whitelist a USB device, plug it in and run:

```bash
diskutil info /Volumes/YOUR_USB_NAME | grep "Volume UUID"
```

Copy the result into `whitelist.json`.

---

## 🛡️ Operational Logic

**Detection:** Monitors `/Volumes` directory for changes.  
**Identification:** Extracts Volume UUID using `diskutil`.  
**Verification:** Compares UUID against `whitelist.json`.  
**Enforcement:** If the UUID is not listed, the system triggers an immediate **Force Unmount**.

---

## ⚠️ Disclaimer
This tool is a Proof of Concept (PoC) for endpoint security automation.  
While effective, it relies on the OS mounting the drive first to read the UUID.  
In high-security air-gapped environments, physical port blocking is recommended.

---

## 👨‍💻 Author
**Osman Kaan Kars**  
Cybersecurity Engineer | SAP Security Specialist  

**LinkedIn:** https://linkedin.com/in/osmankaankars  
**GitHub:** https://github.com/osmankaankars
