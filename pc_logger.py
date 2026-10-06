#!/usr/bin/env python3
"""
PC logger for the Project 13 gateway (Board 2).

Reads the gateway's USB serial output, adds the PC's real date/time to every
line, shows it on screen and appends it to events_YYYY-MM-DD.csv.
This gives the event log real timestamps (the ESP32 has no clock).

Install once:   pip install pyserial
Run:            python pc_logger.py COM5            (Windows)
                python3 pc_logger.py /dev/ttyUSB0   (Linux)
                python3 pc_logger.py /dev/cu.usbserial-0001   (macOS)
Close the Arduino Serial Monitor first: only one program can open the port.
"""
import sys
import datetime
import serial

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

port = sys.argv[1]
ser = serial.Serial(port, 115200, timeout=1)
fname = f"events_{datetime.date.today().isoformat()}.csv"
print(f"Listening on {port}, saving to {fname}  (Ctrl+C to stop)")

with open(fname, "a", encoding="utf-8") as out:
    try:
        while True:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            stamp = datetime.datetime.now().isoformat(timespec="seconds")
            row = f"{stamp},{line}"
            # make alerts stand out on screen
            if line.startswith(("SEC,", "GAP,")) or ",P2," in line or ",P3," in line or "LOST" in line:
                print("!!", row)
            else:
                print("  ", row)
            out.write(row + "\n")
            out.flush()
    except KeyboardInterrupt:
        print("\nStopped.")
