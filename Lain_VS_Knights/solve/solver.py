import hashlib

fragments = {
    "i2c_mirror": "0000_7600",
    "can_checksum": "0026",
    "spi_parity": "15",
    "sram_write": "8b_89",
    "logic_and": "a8_ff",
    "fuse_bits": "30",
    "fault_injection": "2_08",
}

order = [
    "i2c_mirror",
    "can_checksum",
    "spi_parity",
    "sram_write",
    "logic_and",
    "fuse_bits",
    "fault_injection",
]

payload = "".join(fragments[k] for k in order)
print("[*] Payload string :", payload)  # Affiche bien tous les fragments joints, avec leurs _ internes

# Calcul du hash
h = hashlib.sha256(payload.encode()).hexdigest()
exploit = h[:24]
print("[*] Exploit final :", exploit)
