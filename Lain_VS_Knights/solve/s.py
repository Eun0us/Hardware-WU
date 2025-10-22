def count_transitions(b):
    bits = f"{b:08b}"  # binaire sur 8 bits
    count = 0
    for i in range(7):
        if bits[i] != bits[i+1]:
            count += 1
    return count

# Affiche tous les octets avec 5 transitions
for b in range(256):
    if count_transitions(b) == 5:
        print(f"{b:02X}  {b:08b}")
