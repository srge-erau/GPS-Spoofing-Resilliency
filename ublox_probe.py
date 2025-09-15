#!/usr/bin/env python3
"""
ublox_probe.py
Discover and fingerprint a u-blox (EV8/NEO-M8/etc.) GNSS over serial/USB.

What it does:
- Enumerates serial ports (Windows, macOS, Linux).
- Tries a set of baud rates (default: 9600, 38400, 57600, 115200, 230400).
- Sniffs traffic to detect:
  * NMEA sentences ($xxGGA/RMC/.., checksum verified)
  * UBX frames (0xB5 0x62 ... with CK_A/CK_B verified)
- If UBX detected, polls MON-VER to extract firmware/hardware strings.
- Ranks candidates and prints a concise “likely configuration” line.

Limitations:
- Can’t auto-detect I2C or SPI (you’d need adapters; this script is UART/USB-CDC only).
- Some eval boards enumerate multiple /dev/tty*; only one carries GNSS.
- If the module is silent (no messages, UBX disabled), you’ll need to set the correct baud manually.

Author: you
"""

import argparse
import sys
import time
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Set

try:
    import serial
    import serial.tools.list_ports as list_ports
except Exception as e:
    print("ERROR: This script requires pyserial. Install with: pip install pyserial")
    sys.exit(1)

# ---------- UBX helpers ----------

UBX_SYNC = b"\xB5\x62"

def ubx_checksum(payload: bytes) -> Tuple[int, int]:
    """Compute UBX CK_A, CK_B over class..payload."""
    ck_a = 0
    ck_b = 0
    for b in payload:
        ck_a = (ck_a + b) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return ck_a, ck_b

def build_ubx(msg_cls: int, msg_id: int, payload: bytes = b"") -> bytes:
    length = len(payload).to_bytes(2, "little")
    body = bytes([msg_cls, msg_id]) + length + payload
    ck_a, ck_b = ubx_checksum(body)
    return UBX_SYNC + body + bytes([ck_a, ck_b])

def parse_ubx_stream(buf: bytearray) -> List[Tuple[int,int,bytes]]:
    """
    Extract valid UBX messages from buf.
    Returns list of (class, id, payload). Mutates buf by consuming bytes.
    """
    messages = []
    i = 0
    # search and parse in-place
    while True:
        # find sync
        idx = buf.find(UBX_SYNC, i)
        if idx < 0:
            # drop everything before tail
            if len(buf) > 2048:
                del buf[:-4]
            break
        # ensure minimal header
        if len(buf) - idx < 8:
            # wait for more data
            if idx > 0:
                del buf[:idx]
            break
        # parse header
        start = idx
        msg_cls = buf[start+2]
        msg_id  = buf[start+3]
        length  = int.from_bytes(buf[start+4:start+6], "little")
        needed  = 6 + length + 2  # class,id,len(2),payload,ck(2) after sync
        total_needed = 2 + needed # plus sync bytes
        if len(buf) - start < total_needed:
            # incomplete; keep tail
            if start > 0:
                del buf[:start]
            break
        frame = buf[start:start+total_needed]
        payload = frame[6+2:6+2+length]  # after sync(2) + class,id,len(2)
        # Validate checksum
        ck_a, ck_b = ubx_checksum(frame[2:-2])
        if frame[-2] == ck_a and frame[-1] == ck_b:
            messages.append((msg_cls, msg_id, bytes(payload)))
            # consume parsed frame
            del buf[:start+total_needed]
            i = 0
        else:
            # bad sync or checksum; skip the first sync byte to resync
            i = idx + 1
    return messages

# ---------- NMEA helpers ----------

NMEA_RE = re.compile(rb'^\$([^*]+)\*([0-9A-F]{2})\r?\n', re.M)

def nmea_checksum(body: bytes) -> int:
    csum = 0
    for b in body:
        csum ^= b
    return csum

def parse_nmea(buf: bytearray) -> List[Tuple[str, bytes]]:
    """
    Extract valid NMEA sentences. Returns list of (type, full_line).
    Mutates buf by removing consumed lines.
    """
    results = []
    data = bytes(buf)
    for m in NMEA_RE.finditer(data):
        body = m.group(1)  # b'GPGGA,...'
        got = int(m.group(2), 16)
        calc = nmea_checksum(body)
        if got == calc:
            typ = body[:5].decode('ascii', errors='ignore') if len(body) >= 5 else "?????"
            results.append((typ, m.group(0)))
    # Trim processed portion to avoid unbounded growth
    if len(data) > 8192:
        del buf[:len(data)-1024]
    return results

# ---------- Data structures ----------

@dataclass
class ProbeStats:
    port: str
    baud: int
    nmea_count: int = 0
    nmea_types: Counter = field(default_factory=Counter)
    ubx_count: int = 0
    ubx_classid: Counter = field(default_factory=Counter)  # (cls,id) -> count
    mon_ver: Optional[Dict[str, List[str]]] = None
    errors: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        # Weight UBX slightly higher, but NMEA still strong evidence.
        return (self.ubx_count * 5) + (self.nmea_count * 3) + (20 if self.mon_ver else 0)

# ---------- Core scanning ----------

COMMON_BAUDS = [9600, 38400, 57600, 115200, 230400]

def list_all_ports() -> List[str]:
    ports = [p.device for p in list_ports.comports()]
    # Heuristic: prefer likely GNSS CDC/USB serial first.
    prioritized = sorted(
        ports,
        key=lambda s: (
            0 if ("ACM" in s or "usbmodem" in s.lower() or "ttyUSB" in s or "COM" in s) else 1,
            s
        )
    )
    return prioritized

def sniff_port_once(port: str, baud: int, duration: float = 3.0) -> ProbeStats:
    stats = ProbeStats(port=port, baud=baud)
    try:
        ser = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.15,
            write_timeout=0.5,
        )
    except Exception as e:
        stats.errors.append(f"open_failed:{type(e).__name__}:{e}")
        return stats

    try:
        # Short settle; clear input buffer
        ser.reset_input_buffer()
        start = time.time()
        buf = bytearray()
        last_poll = 0.0
        while (time.time() - start) < duration:
            chunk = ser.read(1024)
            if chunk:
                buf.extend(chunk)
                # Parse as it flows
                for typ, line in parse_nmea(buf):
                    stats.nmea_count += 1
                    stats.nmea_types[typ] += 1
                for (c, i, p) in parse_ubx_stream(buf):
                    stats.ubx_count += 1
                    stats.ubx_classid[(c, i)] += 1
            else:
                time.sleep(0.02)

            # If we are seeing UBX but no MON-VER yet, send a poll once per second to try and harvest version.
            if stats.ubx_count > 0 and (time.time() - last_poll) > 1.0 and stats.mon_ver is None:
                try:
                    ser.write(build_ubx(0x0A, 0x04, b""))  # MON-VER poll
                    last_poll = time.time()
                    # Try to read immediate response burst
                    t0 = time.time()
                    burst = bytearray()
                    while time.time() - t0 < 0.4:
                        r = ser.read(2048)
                        if r:
                            burst.extend(r)
                    msgs = parse_ubx_stream(burst)
                    for (c,i,p) in msgs:
                        if (c, i) == (0x0A, 0x04):
                            # Payload: series of zero-terminated strings (SW/HW/EXT)
                            fields = p.split(b"\x00")
                            strings = [s.decode("ascii", errors="ignore") for s in fields if s]
                            # Partition by prefix
                            mon = defaultdict(list)
                            for s in strings:
                                if s.startswith("SW"):
                                    mon["SW"].append(s)
                                elif s.startswith("HW"):
                                    mon["HW"].append(s)
                                else:
                                    mon["EXT"].append(s)
                            stats.mon_ver = dict(mon)
                except Exception as we:
                    # ignore write errors and continue sniffing
                    pass

    except Exception as e:
        stats.errors.append(f"read_failed:{type(e).__name__}:{e}")
    finally:
        try:
            ser.close()
        except Exception:
            pass
    return stats

def rank_and_report(all_stats: List[ProbeStats]) -> None:
    if not all_stats:
        print("No ports scanned. Nothing to report.")
        return

    # Sort by score desc
    sorted_stats = sorted(all_stats, key=lambda s: (s.score, s.ubx_count, s.nmea_count), reverse=True)

    print("\n=== Scan Results (highest confidence first) ===")
    for s in sorted_stats:
        protos = []
        if s.nmea_count:
            protos.append("NMEA")
        if s.ubx_count:
            protos.append("UBX")
        proto_str = "+".join(protos) if protos else "unknown"
        nmea_types = ", ".join(f"{k}:{v}" for k,v in s.nmea_types.most_common(5))
        ubx_heads = ", ".join(f"{cls:02X}-{mid:02X}:{cnt}" for (cls,mid),cnt in s.ubx_classid.most_common(6))
        monver = ""
        if s.mon_ver:
            sw = " | ".join(s.mon_ver.get("SW", [])[:2])
            hw = " | ".join(s.mon_ver.get("HW", [])[:1])
            monver = f"  MON-VER → SW: {sw} ; HW: {hw}"
        err = f"  ERR: {s.errors}" if s.errors else ""
        print(f"[{s.port} @ {s.baud}]  protocols={proto_str}  NMEA={s.nmea_count} ({nmea_types})  UBX={s.ubx_count} ({ubx_heads}){monver}{err}")

    top = sorted_stats[0]
    likely = []
    if top.nmea_count or top.ubx_count:
        likely.append(f"Port={top.port}")
        likely.append(f"Baud={top.baud}")
        if top.nmea_count and top.ubx_count:
            likely.append("Protocols=NMEA+UBX")
        elif top.nmea_count:
            likely.append("Protocols=NMEA")
        elif top.ubx_count:
            likely.append("Protocols=UBX")
        if top.mon_ver:
            sw = "; ".join(top.mon_ver.get("SW", [])[:1])
            hw = "; ".join(top.mon_ver.get("HW", [])[:1])
            likely.append(f"u-blox={sw or 'SW?'} | {hw or 'HW?'}")

    print("\n=== Likely configuration for your full script ===")
    if likely:
        print("  " + "  |  ".join(likely))
    else:
        print("  No clear talker found. Try a different baud set or ensure the receiver is powered and streaming.")

    print("\nNext steps:")
    print("  • Use the Port and Baud above in your main script.")
    print("  • If using UBX, enable/disable specific messages via CFG-MSG and persist with CFG-CFG (save to BBR/Flash).")
    print("  • If only NMEA appeared, your receiver may have UBX disabled on that interface; enable via u-center or CFG-MSG.")
    print("  • On Linux, if you see permission errors: add your user to the 'dialout' group and re-login.")
    print("  • If nothing is detected: try --bauds 4800 9600 19200 38400 57600 115200 230400 and check cabling/USB mode.\n")

def main():
    parser = argparse.ArgumentParser(description="Probe u-blox GNSS over serial/USB and report protocols/baud/ID.")
    parser.add_argument("--ports", nargs="*", default=None,
                        help="Specific port(s) to test (e.g., COM7 / /dev/ttyACM0). Default: scan all detected ports.")
    parser.add_argument("--bauds", nargs="*", type=int, default=None,
                        help=f"Baud rates to try. Default: {COMMON_BAUDS}")
    parser.add_argument("--duration", type=float, default=3.0,
                        help="Seconds to sniff each port/baud.")
    parser.add_argument("--quiet", action="store_true", help="Reduce per-try chatter.")
    args = parser.parse_args()

    ports = args.ports or list_all_ports()
    if not ports:
        print("No serial ports found.")
        sys.exit(2)
    bauds = args.bauds or COMMON_BAUDS

    print(f"Scanning ports: {ports}")
    print(f"Trying bauds:  {bauds}")
    print(f"Sniff duration per (port,baud): {args.duration:.1f}s\n")

    all_stats: List[ProbeStats] = []
    for port in ports:
        for baud in bauds:
            if not args.quiet:
                print(f"--- {port} @ {baud} ---")
            stats = sniff_port_once(port, baud, duration=args.duration)
            all_stats.append(stats)

    rank_and_report(all_stats)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
