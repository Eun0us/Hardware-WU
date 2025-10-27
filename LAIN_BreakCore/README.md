# Write-Up — Lain_BreakCore (ECW — Level 2 UART)

**CTF:** ECW</br>
**Author:** Eun0us</br>
**Difficulty:** Easy

---

## Challenge description

This challenge emulates a UART interface on a router named **LAIN**. You interact with the device over two TCP ports that simulate UART `TX` and `RX`:

* `TX` (read UART)
* `RX` (write UART)

Goal: connect to the UART-like service, recover the firmware, locate the AES key and IV, request the encrypted flag from the device, and decrypt it.

---

## Summary of the solution

1. Connect to the device and dump the firmware by sending `dump_bin` to the `RX` port while reading from `TX`.
2. The firmware is emitted as hex strings — collect them, concatenate, and convert to raw bytes.
3. The firmware bytes are XOR-obfuscated with the repeating key `L41N`. Undo the XOR to recover the real firmware binary.
4. Extract the AES key and IV from the recovered firmware (via static reversing or running the firmware in an AVR emulator such as SimAVR).
5. Send the `flag` command to the device, capture the printed encrypted flag (hex), unhexlify it, then decrypt with AES-CBC using the recovered key and IV.

---

## Step-by-step walkthrough

### 1. Dump the firmware

* Open a TCP connection to the `TX` port (1111) and read all output lines.
* Open a TCP connection to the `RX` port (2222) and send the command `dump_bin\n`.
* The device will print hex-encoded chunks of the firmware to `TX`. Filter out prompts or non-hex output, concatenate hex lines and convert to bytes.

Notes: ignore prompt characters like `>` and blank lines. Some lines may include text; keep only true hex lines.

### 2. Undo XOR obfuscation

* The firmware bytes are obfuscated with a repeating XOR key: `b"L41N"`.
* XOR each byte with the corresponding byte of the repeating key to recover the true binary.
* Save the recovered binary for analysis (e.g. `lain_breakcore_recovered.bin`).

### 3. Extract AES key and IV from the firmware

Two common approaches:

* **Static reverse:** load the recovered binary into Ghidra/IDA and search for 16-byte constant arrays or the AES initialization routine. Look for memory references and static data that match AES keys/IV patterns.
* **Dynamic approach (SimAVR):** run the firmware in an AVR emulator and observe UART output. The firmware may print debug data or memory dumps that reveal the keys.

In this challenge the key and IV were found embedded in the firmware. For reproducibility, the values used here are:

```py
key = bytes([0x13, 0x37, 0xBA, 0xAD, 0xC0, 0xFE, 0x42, 0x42,
             0x01, 0x23, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF])

iv  = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x55, 0x66,
             0x01, 0x10, 0x20, 0x30, 0x99, 0x88, 0x77, 0x66])
```

> In an actual CTF you would extract these values from the recovered binary rather than copying them from this write-up.

### 4. Retrieve the encrypted flag

* Send the `flag\n` command to `RX`. The device prints a line like `Encrypted flag (hex):` followed by the ciphertext on the next line or on the same line.
* Capture the hex string and convert it to bytes.

### 5. Decrypt the flag

* Use AES in CBC mode with the recovered key and IV.
* Decrypt the ciphertext and remove PKCS#7 padding to obtain the plaintext flag.

---

## Full Python implementation

Below is a polished Python script implementing the entire workflow: dumping the firmware, undoing the XOR, extracting the encrypted flag from the device, and decrypting it.

> Requirements: `pycryptodome` (install with `pip install pycryptodome`).

```py
#!/usr/bin/env python3

import socket
import binascii
import threading
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "localhost"
TX_PORT = 1111
RX_PORT = 2222
XOR_KEY = b"L41N"


def dump_firmware(host=HOST, tx_port=TX_PORT, rx_port=RX_PORT, timeout=3.0):
    """Send `dump_bin` to RX and read the hex chunks from TX."""
    firmware_chunks = []
    stop_flag = threading.Event()

    def reader():
        try:
            with socket.create_connection((host, tx_port), timeout=5) as s:
                s.settimeout(0.5)
                buffer = ""
                while not stop_flag.is_set():
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    text = data.decode(errors="ignore")
                    buffer += text
                    while "\n" in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line or line.startswith("<") or line.startswith(">"):
                            continue
                        if all(c in "0123456789abcdef" for c in line.lower()):
                            firmware_chunks.append(line)
        except Exception as e:
            # Reader thread should not crash the whole script
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Send command to request the firmware
    try:
        with socket.create_connection((host, rx_port), timeout=5) as s:
            time.sleep(0.2)
            s.sendall(b"dump_bin\n")
            # allow time for the device to send the full dump
            time.sleep(1.5)
    except Exception as e:
        print(f"[-] Error sending dump command: {e}")

    # Wait a bit for reader to finish
    time.sleep(timeout)
    stop_flag.set()
    t.join(timeout=1.0)

    if not firmware_chunks:
        raise RuntimeError("No firmware chunks received")

    firmware_hex = ''.join(firmware_chunks)
    firmware_bytes = binascii.unhexlify(firmware_hex)
    print(f"[+] Firmware dump received ({len(firmware_bytes)} bytes, XOR-obfuscated)")
    return firmware_bytes


def xor_deobfuscate(data, key=XOR_KEY):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def get_encrypted_flag(host=HOST, tx_port=TX_PORT, rx_port=RX_PORT, timeout=2.0):
    result = []
    stop_flag = threading.Event()

    def reader():
        try:
            with socket.create_connection((host, tx_port), timeout=5) as s:
                s.settimeout(0.5)
                buffer = ""
                while not stop_flag.is_set():
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    out = data.decode(errors="ignore")
                    buffer += out
                    if "Encrypted flag (hex):" in buffer:
                        lines = buffer.splitlines()
                        for idx, line in enumerate(lines):
                            if "Encrypted flag (hex):" in line:
                                # prefer next line if present
                                if idx + 1 < len(lines):
                                    hexline = lines[idx + 1].strip()
                                else:
                                    hexline = line.split("Encrypted flag (hex):", 1)[1].strip()
                                result.append(hexline)
                                stop_flag.set()
                                return
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        with socket.create_connection((host, rx_port), timeout=5) as s:
            time.sleep(0.1)
            s.sendall(b"flag\n")
            time.sleep(0.5)
    except Exception as e:
        print(f"[-] Error sending flag command: {e}")

    # wait for reader
    time.sleep(timeout)
    stop_flag.set()
    t.join(timeout=1.0)

    if not result:
        raise RuntimeError("Could not retrieve encrypted flag from device")

    return result[0]


if __name__ == "__main__":
    # 1) Dump firmware
    fw_xor = dump_firmware()

    # 2) Undo XOR
    fw = xor_deobfuscate(fw_xor)
    with open("lain_breakcore_recovered.bin", "wb") as f:
        f.write(fw)
    print("[+] Recovered firmware saved to lain_breakcore_recovered.bin")

    # 3) Extract key and IV from the firmware (manual step / reversing)
    # For this write-up the values extracted from the firmware are hard-coded here:
    key = bytes([0x13, 0x37, 0xBA, 0xAD, 0xC0, 0xFE, 0x42, 0x42,
                 0x01, 0x23, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF])
    iv  = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x55, 0x66,
                 0x01, 0x10, 0x20, 0x30, 0x99, 0x88, 0x77, 0x66])

    # 4) Get encrypted flag
    enc_hex = get_encrypted_flag()
    print(f"[+] Encrypted flag (hex): {enc_hex}")
    ct = binascii.unhexlify(enc_hex)

    # 5) Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    print('\n[+] FLAG:', pt.decode())
```

---

## Alternative approaches and hints

* If reversing is unfamiliar, run the recovered firmware in an AVR emulator (SimAVR) to observe UART behavior and printed constants.
* Search the binary for sequences of 16 bytes (likely AES keys/IVs) as a heuristic; check whether those values are read into an AES routine.
* If the device prints verbose logs, watch for memory dumps or prints that show the key or intermediate values.

---

## Conclusion

Lain_BreakCore is an approachable UART/firmware challenge that combines basic network interaction with simple firmware recovery and AES decryption. The main skills exercised are: capturing serial output over TCP, simple XOR deobfuscation, static/dynamic firmware analysis, and symmetric decryption.

---
