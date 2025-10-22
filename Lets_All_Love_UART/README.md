# Write-Up Lets All Love UART

**CTF**: ECW
-

- **Difficulty:** very easy
- **Author:** Eun0us

## Description:

```md
    **Level 1 UART - Lets All Love UART**

    This challenge emulates a UART interface on Lain routeur.
    Open both connections, interact as if it's real hardware.
    - `TX`: port 1111 (read UART)
    - `RX`: port 2222 (write UART)

    Let's All Love Lain!
```

## Solve

Realy easy challenge !

Solve with two socket python

```py
import socket
import threading

HOST = "localhost"
TX_PORT = 1111
RX_PORT = 2222

def reader():
    with socket.create_connection((HOST, TX_PORT)) as s:
        while True:
            data = s.recv(4096)
            if not data:
                break
            out = data.decode()
            print(out, end="")
            if "CTF{" in out:
                break

tx_thread = threading.Thread(target=reader, daemon=True)
tx_thread.start()

with socket.create_connection((HOST, RX_PORT)) as s:
    s.sendall(b"flag\n")

tx_thread.join()
```
