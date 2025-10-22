import hashlib

msg = "00_91b30595_5706_ff6b5_20"
print(hashlib.sha256(msg.encode()).hexdigest()[:24])