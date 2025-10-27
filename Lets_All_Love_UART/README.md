# Write-Up — Lets All Love UART (ECW — Level 1 UART)

**CTF:** ECW
**Author:** Eun0us
**Difficulty:** Very Easy

---

## Description

**Level 1 UART — Lets All Love UART**</br>
This challenge emulates a UART interface on a LAIN router. You interact with the device using two TCP ports that simulate UART `TX` and `RX`:

* `TX` (read UART) — port **1111**
* `RX` (write UART) — port **2222**

Goal: open both connections, send the `flag` command to the device, and read the returned flag from the UART output.

---

## Summary of the solution

1. Open a persistent reader on `TX` (port 1111) to capture device output.
2. Send the `flag` command to `RX` (port 2222).
3. Read the printed output from `TX` and extract the flag (expected format `ECW{...}`).

This is a straightforward network/serial interaction exercise — no reversing or cryptography required.

---

## Step-by-step walkthrough

1. Start a TCP connection to the `TX` port and continuously read data. Print each received chunk to the console.
2. While the reader runs, connect to `RX` and send the `flag\n` command.
3. The device prints the flag on the `TX` stream. Terminate once the `ECW{...}` marker is detected.

Hints:

* Use a background thread (or a separate process) to read `TX` while writing to `RX` concurrently.
* Use a tolerant string decoding strategy to avoid crashes on unexpected bytes.
* For remote targets, replace `localhost` with the target IP and ensure ports are reachable.

---

## Clean Python implementation

This polished script performs the required steps cleanly and robustly. It prints device output as it arrives and exits after detecting the flag.

```py
#!/usr/bin/env python3
"""
Solver for 'Lets All Love UART' (ECW Level 1).

- Reads from TX (port 1111) in a background thread.
- Sends "flag\n" to RX (port 2222).
- Prints received output and exits once a ECW{...} flag is seen.
"""

import socket
import threading
import sys
import time
import re

HOST = "localhost"
TX_PORT = 1111
RX_PORT = 2222
FLAG_RE = re.compile(r"ECW\{[^}]+\}")


def tx_reader(host=HOST, port=TX_PORT, stop_event=None):
    """Continuously read from TX and print output. Stop when flag is found."""
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.settimeout(0.5)
            buffer = ""
            while not (stop_event and stop_event.is_set()):
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                text = data.decode(errors="replace")
                print(text, end="", flush=True)
                buffer += text
                m = FLAG_RE.search(buffer)
                if m:
                    print("\n[+] Flag found:", m.group(0))
                    if stop_event:
                        stop_event.set()
                    return
    except Exception as e:
        print(f"[-] TX reader error: {e}", file=sys.stderr)
        if stop_event:
            stop_event.set()


def send_flag_command(host=HOST, port=RX_PORT):
    """Connect to RX and send the 'flag' command."""
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(b"flag\n")
            time.sleep(0.2)
    except Exception as e:
        print(f"[-] RX write error: {e}", file=sys.stderr)


if __name__ == "__main__":
    stop_event = threading.Event()
    t = threading.Thread(target=tx_reader, kwargs={"stop_event": stop_event}, daemon=True)
    t.start()

    # Give the reader a short moment to establish
    time.sleep(0.1)
    send_flag_command()

    # Wait until flag is seen or reader finishes
    t.join(timeout=10)
    if not stop_event.is_set():
        print("[-] Flag not found within timeout.", file=sys.stderr)
        sys.exit(1)
```

---

## Alternatives & tips

* Quick `netcat` approach: you can use two `nc` sessions — one to listen/read `TX`, another to connect to `RX` and send `flag`. The Python solution is more portable and handles buffering and timeout cleanly.
* If the flag is not printed, verify the host/port and that the service is up. Firewalls or NAT may block connectivity.

---

## Conclusion

This challenge tests basic skills in interacting with network-exposed serial interfaces: opening concurrent read/write channels and parsing output. It is ideal for beginners learning about UART-over-TCP and simple exploitation workflows.

---
