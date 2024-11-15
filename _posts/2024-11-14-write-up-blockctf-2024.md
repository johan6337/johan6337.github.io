---
layout: post
title: Writeups for BlockCTF 2024
description: Some crypto challenge writeups.
date: '2024-11-14 21:44:00 +0700'
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---
 
Crypto challenges in this ctf is quite easy, but I still want to write it up. I solved 2 out of 3 chals. The first one is so guessy so i skip it (i hate these chals). There are no solution codes cuz the ideas are so clearly.JUST DO IT!!!

## 1. Where's my key ## 

### Problem code ### 

```python
import os
import socketserver
import json

import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST_PORT = int(os.environ.get("HOST_PORT", "8000"))
FLAG = os.environ.get("FLAG", "flag{this-is-not-the-real-flag}")
X25519_KEY_SIZE = 32


class Handler(socketserver.BaseRequestHandler):
    timeout = 5.0

    def handle(self):
        request = json.loads(self.request.recv(1024))
        client_pub = bytes.fromhex(request.get("client_pub", ""))
        if len(client_pub) != X25519_KEY_SIZE:
            return

        server_priv = os.urandom(X25519_KEY_SIZE)
        server_pub = x25519.scalar_base_mult(server_priv)
        secret = x25519.scalar_mult(server_priv, client_pub)

        response = {"server_pub": server_pub.hex()}

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(secret), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(FLAG.encode()) + encryptor.finalize()

        data = {"iv": iv.hex(), "ct": ct.hex()}

        # This is how you combine dictionaries... right?
        response = response and data

        self.request.sendall(json.dumps(response).encode())


class Server(socketserver.ThreadingTCPServer):
    request_queue_size = 100


def main(host="0.0.0.0", port=HOST_PORT):
    print(f"Running server on {host}:{port}")
    server = Server((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
```

### Solution ###
It just a simple x25519 key exchange, then encrypt the flag with AES-CTR. The problem is the response is wrong, it should be `response.update(data)` instead of `response = response and data`. So we dont have the server_pub key in the response, which is nessessary to decrypt the flag. But we can just send the b'0' * 32 as our public key, then the secret must be b'0' * 32 too. So we can decrypt the flag with the secret.


## 2. Glitch in the Crypt: Exploiting Faulty RSA Decryption ##

### Problem code ### 

```python
import os
import random

from Crypto.Util.number import inverse

# RSA public parameters
# Corrected modulus n = p * q
p = None # Hidden
q = None # Hidden
n = 30392456691103520456566703629789883376981975074658985351907533566054217142999128759248328829870869523368987496991637114688552687369186479700671810414151842146871044878391976165906497019158806633675101
e = 65537

# Encrypted flag
flag = os.environ.get("FLAG", "flag{not_the_real_flag}")
flag_int = int.from_bytes(flag.encode(), 'big')
flag_bytes = flag.encode()
flag_length = len(flag_bytes)
ciphertext = pow(flag_int, e, n)

# Ensure n is correct
assert p * q == n

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

dP = d % (p - 1)
dQ = d % (q - 1)
qInv = inverse(q, p)

def decrypt(c_hex):
    try:
        c = int(c_hex, 16)
    except ValueError:
        return None, False, "Invalid ciphertext format. Please provide hexadecimal digits."
    if c >= n:
        return None, False, "Ciphertext must be less than modulus n."
    if c == ciphertext:
        return None, False, "Can't use the flag!"

    # Simulate fault occurrence
    faulty = random.randint(1, 10) == 1  # Fault occurs 1 in 10 times

    # Decrypt using CRT
    m1 = pow(c, dP, p)
    m2 = pow(c, dQ, q)
    if faulty:
        # Introduce fault in m1
        m1 = random.randrange(1, p)
    # Combine using CRT
    h = (qInv * (m1 - m2)) % p
    m = (m2 + h * q) % n
    return m, faulty, None


def main():
    print("Welcome to the RSA Decryption Oracle!")
    print("You can decrypt your own ciphertexts.")
    print("Retrieve the encrypted flag to get the secret message.")
    print("Type 'flag' to get the encrypted flag.")
    print("Type 'exit' to quit.")
    while True:
        print("\nSend your ciphertext in hex format:")
        c_hex = input().strip()
        if not c_hex:
            break
        if c_hex.lower() == 'exit':
            print("Goodbye!")
            break
        elif c_hex.lower() == 'flag':
            print(f"Encrypted flag (hex): {hex(ciphertext)}")
            print(f"Flag length (bytes): {flag_length}")
            continue
        m, faulty, error = decrypt(c_hex)
        if error:
            print(error)
        else:
            print(f"Decrypted message (hex): {hex(m)}")
            if faulty:
                print("Note: Fault occurred during decryption.")


if __name__ == "__main__":
    main()
```

### Solution ###
This is a typical RSA-CRT decryption but it has a fault in m1. It can leak the factor p of N by decrypt the same ciphertext multiple times. Obtain 2 plaintexts m and m' which m is the correct one and m' is the faulty one. Then we can calculate m - m' = k*q mod n which is a multiple of q. Then we can calculate q = gcd(n, m - m'). Then we can calculate p = n // q. Then we can decrypt the flag with p and q.



