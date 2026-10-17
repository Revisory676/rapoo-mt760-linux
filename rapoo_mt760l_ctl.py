#!/usr/bin/env python3
"""
Rapoo MT760L Wireless / Wired Mouse Linux Driver Utility
Reverse-engineered from RapooDevice.dll & MT760LDriver.exe via Ghidra + REA.

Supports:
- Wireless 2.4GHz mode via Dongle 2 (24ae:1870):
    Telink TLSR8355 receiver streams asynchronous 7-byte telemetry packets
    (UsagePage=0xFF00, Report ID=0xBB) on the Interrupt IN endpoint:
    - Byte 0: 0xBB (Report ID)
    - Byte 1: 0xB0 (Opcode)
    - Byte 2: 0x01
    - Bytes 3..4: Active DPI resolution (16-bit Little-Endian, e.g. 800, 1000, 1200, 1600, 2400, 3200, 4000)
    - Byte 5: Power State (0x01 = Active/Discharging, 0x02 = Charging, 0x00 = Standby)
    - Byte 6: Battery Percentage (0-100%)
- Wired USB mode (24ae:4500):
    Direct vendor protocol on UsagePage=0xFFEF, Report ID=0x05.
    Queries hardware RF pairing address and device authentication token.
- Bootloader Detection (24ae:3040):
    Detects when receiver is in Telink DFU mode.
- Caching & Daemon mode:
    Stores last known telemetry in ~/.cache/rapoo_mt760l.json so battery
    status remains instantly queryable even when the mouse is asleep.
"""

import argparse
import datetime
import fcntl
import glob
import json
import os
import select
import struct
import sys
import time

CACHE_FILE = os.path.expanduser("~/.cache/rapoo_mt760l.json")
TOKEN_CACHE_FILE = os.path.expanduser("~/.cache/rapoo_mt760l_token.json")

DPI_PRESETS = {
    800: "Stage 1 (800 DPI)",
    1000: "Stage 2 (1000 DPI)",
    1200: "Stage 3 (1200 DPI)",
    1600: "Stage 4 (1600 DPI)",
    2400: "Stage 5 (2400 DPI)",
    3200: "Stage 6 (3200 DPI)",
    4000: "Stage 7 (4000 DPI)",
}


def Hidiocsoutput(length: int) -> int:
    return 0xC0000000 | (length << 16) | (ord('H') << 8) | 0x0B

def Hidiocginput(length: int) -> int:
    return 0xC0000000 | (length << 16) | (ord('H') << 8) | 0x0A


def save_cache(data: dict) -> None:
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_cache() -> dict | None:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def save_token_cache(data: dict) -> None:
    try:
        with open(TOKEN_CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_token_cache() -> dict | None:
    if os.path.exists(TOKEN_CACHE_FILE):
        try:
            with open(TOKEN_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def find_all_rapoo_devices() -> dict[str, str]:
    """Inspect sysfs and return mapping of connected Rapoo devices:
    'wired', 'wireless', 'wireless_pairing', 'bootloader'."""
    devices = {}
    for syspath in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        uevent_path = os.path.join(syspath, "device", "uevent")
        rdesc_path = os.path.join(syspath, "device", "report_descriptor")
        if not os.path.exists(uevent_path) or not os.path.exists(rdesc_path):
            continue
        with open(uevent_path, "r", encoding="utf-8", errors="ignore") as f:
            uevent = f.read().upper()
        with open(rdesc_path, "rb") as f:
            rdesc = f.read()

        dev_node = "/dev/" + os.path.basename(syspath)

        # Wired interface: 24ae:4500, UsagePage 0xFFEF, Report ID 0x05 (85 05)
        if "000024AE:00004500" in uevent and b"\x06\xef\xff" in rdesc and b"\x85\x05" in rdesc:
            devices["wired"] = dev_node

        # Wireless telemetry interface: 24ae:1870, UsagePage 0xFF00, Report ID 0xBB (85 bb)
        if "000024AE:00001870" in uevent and b"\x06\x00\xff" in rdesc and b"\x85\xbb" in rdesc:
            devices["wireless"] = dev_node

        # Wireless pairing/control interface: 24ae:1870 with Report ID 0xBA (85 ba)
        if "000024AE:00001870" in uevent and b"\x85\xba" in rdesc:
            devices["wireless_pairing"] = dev_node

        if "000024AE:00003040" in uevent:
            devices["bootloader"] = dev_node

    return devices


def find_rapoo_hidraw(preferred_mode: str | None = None) -> tuple[str, str]:
    """Locate the /dev/hidrawX node for Rapoo MT760L.
    Priority: Wired > Wireless > Bootloader (or preferred_mode if specified)."""
    devices = find_all_rapoo_devices()

    if preferred_mode and preferred_mode in devices:
        return devices[preferred_mode], preferred_mode

    if "wired" in devices:
        return devices["wired"], "wired"

    if "wireless" in devices:
        return devices["wireless"], "wireless"

    if "bootloader" in devices:
        raise RuntimeError(
            "Rapoo Receiver is in Bootloader Mode (24ae:3040). "
            "Please plug in Dongle 2 (24ae:1870) for wireless use, or connect the mouse via USB-C cable."
        )

    raise RuntimeError(
        "Rapoo MT760L not detected in wired (24ae:4500) or wireless (24ae:1870) mode. "
        "Please insert Dongle 2 or connect the mouse via USB-C."
    )


def parse_telemetry_packet(data: bytes) -> dict | None:
    if not data:
        return None
    if data[0] == 0xBB and len(data) >= 7:
        bat = min(100, data[6])
        power_code = data[5]
        if power_code == 0x01:
            power_str = "Online / Active"
        elif power_code == 0x00:
            power_str = "Standby / Sleep"
        elif power_code == 0x02:
            power_str = "Charging"
        else:
            power_str = f"Status 0x{power_code:02X}"

        # Bytes 3 and 4 are 16-bit little-endian DPI
        dpi_val = int.from_bytes(data[3:5], "little")
        dpi_label = DPI_PRESETS.get(dpi_val, f"{dpi_val} DPI")

        return {
            "report_id": "0xBB",
            "battery_percent": bat,
            "power_state": power_str,
            "dpi_value": dpi_val,
            "dpi_label": dpi_label,
            "raw": " ".join(f"{b:02x}" for b in data),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    elif data[0] == 0xBA and len(data) >= 32:
        mouse_rf = struct.unpack(">I", data[1:5])[0]
        bat = data[5]
        gear = data[6]
        words = struct.unpack(">6I", data[7:31])
        return {
            "report_id": "0xBA",
            "battery_percent": bat,
            "power_state": "Active",
            "dpi_value": None,
            "dpi_label": f"Gear {gear}",
            "mouse_rf_id": f"0x{mouse_rf:08X}",
            "config_words": [f"0x{w:08X}" for w in words],
            "raw": " ".join(f"{b:02x}" for b in data),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    return None


def read_wireless_telemetry(fd: int, timeout: float = 2.5) -> dict | None:
    """Read live wireless telemetry from Rapoo Dongle 2 (24ae:1870)."""
    # 1. Check if unread report is already waiting in the kernel buffer
    r, _, _ = select.select([fd], [], [], 0)
    if r:
        data = os.read(fd, 64)
        parsed = parse_telemetry_packet(data)
        if parsed:
            save_cache(parsed)
            return parsed

    # 2. Wait for incoming packet
    t0 = time.time()
    while time.time() - t0 < timeout:
        r, _, _ = select.select([fd], [], [], 0.5)
        if not r:
            continue
        data = os.read(fd, 64)
        parsed = parse_telemetry_packet(data)
        if parsed:
            save_cache(parsed)
            return parsed

    return None


def monitor_wireless(fd: int) -> None:
    """Continuously monitor and stream live telemetry updates."""
    print("Monitoring Rapoo MT760L wireless telemetry (Press Ctrl+C to stop)...")
    last_bat = None
    last_dpi = None
    last_state = None

    while True:
        r, _, _ = select.select([fd], [], [], 1.0)
        if not r:
            continue
        data = os.read(fd, 64)
        parsed = parse_telemetry_packet(data)
        if parsed:
            save_cache(parsed)
            bat = parsed["battery_percent"]
            dpi = parsed["dpi_label"]
            state = parsed["power_state"]
            now = datetime.datetime.now().strftime("%H:%M:%S")

            if (bat != last_bat) or (dpi != last_dpi) or (state != last_state):
                print(f"[{now}] Battery: {bat}% | State: {state} | DPI: {dpi} | Raw: {parsed['raw']}")
                last_bat = bat
                last_dpi = dpi
                last_state = state


def read_wired_status(fd: int) -> dict:
    """Query wired MT760L (24ae:4500) via Report ID 0x05, Opcode 0x01."""
    req = bytearray(64)
    req[0] = 0x05
    req[1] = 0x01
    try:
        fcntl.ioctl(fd, Hidiocsoutput(64), req, True)
    except OSError:
        os.write(fd, bytes(req))
    time.sleep(0.02)
    inbuf = bytearray(64)
    inbuf[0] = 0x05
    try:
        fcntl.ioctl(fd, Hidiocginput(64), inbuf, True)
        resp = bytes(inbuf)
    except OSError:
        resp = os.read(fd, 64)

    rf_bytes = resp[4:8]
    rf_id = struct.unpack(">I", rf_bytes)[0]
    token = resp[8:12].hex()

    result = {
        "raw": " ".join(f"{b:02x}" for b in resp[:16]),
        "mouse_rf_id": f"0x{rf_id:08X} (bytes: {rf_bytes.hex(' ')})",
        "device_token": f"0x{token.upper()}",
        "token_hex": token,
        "rf_id_hex": rf_bytes.hex(),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    # Automatically cache token for wireless pairing use
    save_token_cache(result)
    return result


def pair_mouse(timeout: int = 30) -> bool:
    """Execute the Rapoo wireless pairing sequence decoded from Frame 893 to 1419.
    1. Obtains authentication token (from wired connection or cache).
    2. Sends pairing beacon to receiver (Report 0xBA, Opcode 0xA0).
    3. Polls receiver state until mouse Left+Middle+Right buttons are pressed for 3s.
    4. Receives 01 01 01 ACK and cleanly exits pairing mode."""
    print("=" * 65)
    print("  RAPOO MT760L WIRELESS PAIRING UTILITY")
    print("=" * 65)

    devices = find_all_rapoo_devices()

    # Step 1: Obtain hardware authentication token
    token_bytes = None
    if "wired" in devices:
        try:
            w_fd = os.open(devices["wired"], os.O_RDWR)
            try:
                w_info = read_wired_status(w_fd)
                token_hex = w_info.get("token_hex")
                if token_hex and len(token_hex) == 8:
                    token_bytes = bytes.fromhex(token_hex)
                    print(f"[*] Found live wired mouse ({devices['wired']}).")
                    print(f"[*] Retrieved hardware auth token : 0x{token_hex.upper()}")
            finally:
                os.close(w_fd)
        except Exception as e:
            print(f"[*] Note: Could not query wired mouse directly ({e})")

    if token_bytes is None:
        cached = load_token_cache()
        if cached and "token_hex" in cached:
            token_hex = cached["token_hex"]
            token_bytes = bytes.fromhex(token_hex)
            print(f"[*] Using cached authentication token : 0x{token_hex.upper()} (from {cached.get('timestamp', 'recent session')})")
        else:
            print("❌ ERROR: Hardware authentication token not found.")
            print("Please connect the Rapoo MT760L mouse via USB-C cable ONCE so the utility can read its token.")
            return False

    # Step 2: Locate wireless receiver
    receiver_node = devices.get("wireless_pairing") or devices.get("wireless")
    if not receiver_node:
        print("❌ ERROR: No Rapoo wireless receiver (24ae:1870) detected.")
        print("Please ensure your USB receiver (Dongle 2) is plugged in.")
        return False

    print(f"[*] Opening wireless receiver at {receiver_node}...")
    fd = os.open(receiver_node, os.O_RDWR)
    try:
        # Step 3: Send pairing beacon (Frame 893)
        # [0xBA, 0xA0, 0x81, 0x01, 0x00, 0xFF*8, 0xC8, 0x00*7, token[0..3], 0x00*7]
        pkt = bytearray(32)
        pkt[0] = 0xBA
        pkt[1] = 0xA0
        pkt[2] = 0x81
        pkt[3] = 0x01
        pkt[4] = 0x00
        for i in range(5, 13):
            pkt[i] = 0xFF
        pkt[13] = 0xC8
        pkt[21:25] = token_bytes
        fcntl.ioctl(fd, Hidiocsoutput(32), pkt)

        print("[*] Receiver is now in pairing mode (listening on 2.4GHz)!")
        print("\n" + "!" * 65)
        print("👉 ACTION REQUIRED ON YOUR RAPOO MT760L MOUSE:")
        print("   1. Switch the bottom slider to 2.4G mode (green LED indicator).")
        print("   2. Press and HOLD the LEFT CLICK + MIDDLE WHEEL + RIGHT CLICK")
        print("      buttons simultaneously for 3 SECONDS.")
        print("!" * 65 + "\n")

        poll_cmd = bytearray(32)
        poll_cmd[0] = 0xBA
        poll_cmd[1] = 0xA1
        poll_cmd[2] = 0x01

        t0 = time.time()
        paired = False

        while time.time() - t0 < timeout:
            try:
                fcntl.ioctl(fd, Hidiocsoutput(32), poll_cmd)
            except OSError:
                pass
            time.sleep(0.04)

            inbuf = bytearray(32)
            inbuf[0] = 0xBA
            try:
                fcntl.ioctl(fd, Hidiocginput(32), inbuf)
            except OSError:
                time.sleep(0.1)
                continue

            # Frame 1418: [0x01, 0x01, 0x01] = Pairing confirmed!
            if inbuf[0] == 0x01 and inbuf[1] == 0x01 and inbuf[2] == 0x01:
                paired = True
                break

            rem = max(0, int(timeout - (time.time() - t0)))
            sys.stdout.write(f"\r⏳ Waiting for 3-button mouse beacon... ({rem}s remaining)  ")
            sys.stdout.flush()
            time.sleep(0.16)

        sys.stdout.write("\n")

        # Step 4: Cleanly exit pairing mode (Frame 1419)
        exit_pkt = bytearray(32)
        exit_pkt[0] = 0xBA
        exit_pkt[1] = 0xA1
        exit_pkt[2] = 0x80
        try:
            fcntl.ioctl(fd, Hidiocsoutput(32), exit_pkt)
        except OSError:
            pass

        if paired:
            print("\n🎉 SUCCESS: Rapoo MT760L is now successfully paired to the receiver!")
            print("You can now use the mouse wirelessly on 2.4GHz.")
            return True
        else:
            print("\n❌ TIMEOUT: Receiver did not detect the mouse pairing beacon.")
            print("Tips for troubleshooting:")
            print("- Ensure the bottom channel selector switch is set to 2.4G (not Bluetooth).")
            print("- Keep the mouse within 20cm of the dongle during the 3-button hold.")
            print("- Hold Left + Middle (Scroll Wheel) + Right buttons firmly together for 3-4 full seconds.")
            return False

    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rapoo MT760L Wireless / Wired Mouse Linux Driver Utility")
    parser.add_argument("--status", action="store_true", help="Read device battery, DPI gear, and connection status")
    parser.add_argument("--pair", action="store_true", help="Pair wireless mouse to receiver (decoded Frame 893-1419 protocol)")
    parser.add_argument("--wired", action="store_true", help="Force query wired USB interface (24ae:4500)")
    parser.add_argument("--wireless", action="store_true", help="Force query wireless receiver interface (24ae:1870)")
    parser.add_argument("--monitor", action="store_true", help="Live stream telemetry events (battery, DPI button presses)")
    parser.add_argument("--daemon", action="store_true", help="Run background monitor daemon updating ~/.cache/rapoo_mt760l.json")
    args = parser.parse_args()

    if args.pair:
        success = pair_mouse()
        sys.exit(0 if success else 1)

    if not args.status and not args.monitor and not args.daemon and not args.wired and not args.wireless:
        args.status = True

    pref = None
    if args.wired:
        pref = "wired"
    elif args.wireless:
        pref = "wireless"

    dev_path, mode = find_rapoo_hidraw(preferred_mode=pref)
    if not args.daemon:
        print(f"Found Rapoo MT760L vendor HID device: {dev_path} (Mode: {mode.upper()})")

    fd = os.open(dev_path, os.O_RDWR | os.O_NONBLOCK)
    try:
        if mode == "wired":
            info = read_wired_status(fd)
            print(f"Connection Type   : Wired USB (24ae:4500)")
            print(f"Mouse RF Address  : {info['mouse_rf_id']}")
            print(f"Device Auth Token : {info['device_token']}")
            print(f"Raw 0x05 Response : {info['raw']}")
            print("Note: In wired mode, mouse is charging and tracking directly over USB.")
        else:
            if args.monitor or args.daemon:
                monitor_wireless(fd)
            else:
                info = read_wireless_telemetry(fd, timeout=2.5)
                if info:
                    print(f"Connection Type   : Wireless 2.4GHz (Dongle 2, 24ae:1870)")
                    print(f"Battery Level     : {info['battery_percent']}%")
                    print(f"Power State       : {info['power_state']}")
                    print(f"Active DPI        : {info['dpi_label']}")
                    print(f"Raw HID Report    : {info['raw']}")
                else:
                    cached = load_cache()
                    if cached:
                        bat = cached.get("battery_percent", cached.get("battery", "Unknown"))
                        print(f"Connection Type   : Wireless 2.4GHz (Dongle 2, 24ae:1870)")
                        print(f"Battery Level     : {bat}% (Last recorded; mouse currently sleeping)")
                        print(f"Power State       : {cached.get('power_state', 'Unknown')}")
                        print(f"Active DPI        : {cached.get('dpi_label', cached.get('dpi_gear', 'Unknown'))}")
                        print(f"Last Recorded At  : {cached.get('timestamp', 'Unknown')}")
                        print("Tip: Click the DPI switch or use `--daemon` for continuous background tracking.")
                    else:
                        print(f"Connection Type   : Wireless 2.4GHz (Dongle 2, 24ae:1870)")
                        print("Telemetry Status  : Mouse is currently sleeping or idle.")
                        print("Tip: Click the DPI switch, then re-run `--status` to capture live battery.")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
