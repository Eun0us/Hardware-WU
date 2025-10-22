import socket
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import threading
import time

HOST = "localhost"
TX_PORT = 1111
RX_PORT = 2222

XOR_KEY = b"L41N"

def dump_bin():
    firmware_chunks = []
    stop = False

    def reader():
        with socket.create_connection((HOST, TX_PORT)) as s:
            buffer = ""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                text = data.decode(errors="ignore")
                buffer += text
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    # Ignore prompt or intro
                    if line.startswith(">") or not line:
                        continue
                    if all(c in "0123456789abcdef" for c in line.lower()) and len(line) >= 2:
                        firmware_chunks.append(line)
                    if "Disconnected" in line or ">" in line:
                        break

    tx_thread = threading.Thread(target=reader, daemon=True)
    tx_thread.start()

    with socket.create_connection((HOST, RX_PORT)) as s:
        time.sleep(0.3)
        s.sendall(b"dump_bin\n")
        time.sleep(1.5)  # Laisse le temps de tout recevoir

    tx_thread.join(timeout=3)
    # Reconstitue le binaire
    firmware_hex = ''.join(firmware_chunks)
    firmware_bytes = binascii.unhexlify(firmware_hex)
    print(f"[+] Firmware dump received ({len(firmware_bytes)} bytes, XOR-obfuscated)")
    return firmware_bytes

def unxor_firmware(xor_bytes, key=XOR_KEY):
    unxored = bytes([b ^ key[i % len(key)] for i, b in enumerate(xor_bytes)])
    print("[+] Firmware unxor done.")
    # Pour debug, sauvegarde le .bin
    with open("lain_breakcore_recovered.bin", "wb") as f:
        f.write(unxored)
    print("[+] Firmware saved as lain_breakcore_recovered.bin")
    return unxored

def get_flag_encrypted():
    result = []

    def reader():
        with socket.create_connection((HOST, TX_PORT)) as s:
            buffer = ""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                out = data.decode(errors="ignore")
                buffer += out
                if "Encrypted flag (hex):" in out:
                    # Flag on line after the message
                    lines = buffer.splitlines()
                    for idx, line in enumerate(lines):
                        if "Encrypted flag (hex):" in line:
                            # Try next line
                            if idx + 1 < len(lines):
                                hexline = lines[idx + 1].strip()
                            else:
                                # Or after colon
                                hexline = line.split("Encrypted flag (hex):")[1].strip()
                            result.append(hexline)
                            return

    tx_thread = threading.Thread(target=reader, daemon=True)
    tx_thread.start()
    with socket.create_connection((HOST, RX_PORT)) as s:
        time.sleep(0.2)
        s.sendall(b"flag\n")
        time.sleep(0.5)
    tx_thread.join(timeout=2)
    if not result:
        print("[-] Could not get encrypted flag!")
        exit(1)
    return result[0]

# ---- Démarrage ----

# 1. Dump firmware
fw_xor = dump_bin()
fw = unxor_firmware(fw_xor)

# 2. Clé/IV extraites manuellement du firmware récupéré
# (Ici, tu les mets à la main, dans le vrai CTF, on utiliserait Ghidra, strings, etc.)
# Clé/IV extraites du firmware Call on main task 
key = bytes([0x13, 0x37, 0xBA, 0xAD, 0xC0, 0xFE, 0x42, 0x42, 0x01, 0x23, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF])
iv  = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x55, 0x66, 0x01, 0x10, 0x20, 0x30, 0x99, 0x88, 0x77, 0x66])

# 3. Récupère le flag chiffré
flag_hex = get_flag_encrypted()
ct = binascii.unhexlify(flag_hex)

# 4. Decrypt AES
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
print("\n[+] FLAG:", pt.decode())
