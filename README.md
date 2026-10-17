# Rapoo MT760 / MT760L Linux Driver & CLI Utility

[![Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.kernel.org/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A standalone userspace Linux driver and CLI utility for the **Rapoo MT760 / MT760L / MT760 Mini** multi-mode ergonomic wireless mouse.

Reverse-engineered from official vendor binaries (`RapooDevice.dll` & `MT760LDriver.exe`) to provide native hardware telemetry, DPI switching, and pairing controls without Wine or proprietary background services.

---

## 🖱️ Supported Hardware

| Mode | USB Vendor ID | USB Product ID | Description |
| :--- | :--- | :--- | :--- |
| **Wireless 2.4GHz** | `24ae` | `1870` | Telink TLSR8355 Wireless Gaming Receiver |
| **Wired USB-C** | `24ae` | `4500` | Direct USB Composite Device |
| **Recovery Mode** | `24ae` | `3040` | Telink DFU / OTA Bootloader |

---

## ✨ Features

- **Live Battery Telemetry:** Reads exact battery percentage, power state (`Active / Discharging`, `Charging`, `Standby`), and RF address.
- **7-Stage DPI Switching:** Set hardware DPI across 7 stages:
  - `800`, `1000`, `1200`, `1600`, `2400`, `3200`, `4000` DPI.
- **Polling Rate Configuration:** Switch report rate (125Hz, 250Hz, 500Hz, 1000Hz).
- **Continuous Monitoring:** Real-time stream of incoming Interrupt IN telemetry packets (`0xBB 0xB0`).
- **Receiver Recovery:** Automatic diagnostic advice and recovery commands if a dongle is trapped in bootloader mode (`24ae:3040`).
- **Zero Kernel Modules Needed:** Runs entirely in userspace using standard Linux `hidraw` and `pyusb` / `evdev`.

---

## ⚡ Installation & Setup

### 1. Install Dependencies
On Arch Linux / CachyOS:
```bash
sudo pacman -S python python-pyusb
```
On Ubuntu / Debian:
```bash
sudo apt install python3 python3-usb
```

### 2. Install Udev Rules (Non-Root Access)
Copy the udev rule to allow your user account to access the mouse without `sudo`:
```bash
sudo cp udev/90-rapoo-mt760.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### 3. Make Executable & Link
```bash
chmod +x rapoo_mt760l_ctl.py
sudo ln -sf "$(pwd)/rapoo_mt760l_ctl.py" /usr/local/bin/rapoo-ctl
```

---

## 🚀 CLI Usage

### Check Device Status & Battery
```bash
rapoo-ctl --status
```
Example Output:
```text
=== Rapoo MT760L Status ===
Found device at: /dev/hidraw10 (Bus 001 Device 006)
Dongle RF Address: 0x937F5589
Mouse RF Address:  0x937F5589 (Paired & Synced)
Battery Level:     97%
Power State:       Online / Active
Active DPI:        Stage 1 (800 DPI)
```

### Switch DPI
```bash
# Set DPI to 1600 (Stage 4)
rapoo-ctl --set-dpi 1600

# Set DPI to 2400 (Stage 5)
rapoo-ctl --set-dpi 2400
```

### Continuous Telemetry Stream
Listen for asynchronous state updates sent by the Telink receiver:
```bash
rapoo-ctl --monitor
```

### Output Raw JSON (for scripts/bars like Waybar/Polybar)
```bash
rapoo-ctl --status --json
```

---

## 🔬 Reverse-Engineered Protocol Overview

The Telink TLSR8355 receiver exposes vendor HID interfaces under `UsagePage=0xFF00, Usage=0x0E`:

1. **Telemetry Stream (Interrupt IN, Report ID `0xBB`):**
   - Packets are 7 bytes long:
     - Byte 0: `0xBB` (Report ID)
     - Byte 1: `0xB0` (Opcode)
     - Byte 2: `0x01`
     - Bytes 3..4: Active DPI resolution (16-bit Little-Endian)
     - Byte 5: Power State (`0x01` = Active, `0x02` = Charging, `0x00` = Standby)
     - Byte 6: Battery Percentage (`0..100%`)

2. **Command Interface (Feature Reports, Report ID `0xBA`):**
   - Commands are 32-byte payloads:
     - `0xAC`: Query 32-bit big-endian Dongle RF Address.
     - `0xAE 0x01` followed by `0xAE 0x00`: Read complete mouse status and calibration block.
     - `0xB0`: Send configuration and DPI table writes.

---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE).
Part of the [Nexus Peripheral Control](https://github.com/Revisory676/nexus-peripheral-control) hardware suite.
