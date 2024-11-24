---
layout: post
title: Writeups for GlacierCTF 2024
description: Some crypto challenge writeups.
date: '2024-11-24 19:37:00 +0700'
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---


This weeks i participated in this ctf and i solved 2 out of 3 chals. The first one is quite easy but the second one took me a lot of time to solve. I have the idea for it in about 30 minutes but get stuck for half of a day cuz my code is wrong. I always encounter many bugs when coding the sol code for internal symmetric cypher challenges lol. I have to be more careful next time.

## 1. Rivest–Shamir–Adleman-Germain ##

### Problem code ###

```python
import os

from Crypto.Util.number import getPrime
from Crypto.Util.number import isPrime
from Crypto.Util.number import bytes_to_long

def generate_primes():
    while True:
        p = getPrime(512),
        q = (2*p) + 1
        r = (2*q) + 1
        s = (2*r) + 1

        if isPrime(q) and isPrime(r) and isPrime(s):
            break
    
    return (p, q, r, s)


def main() -> int:
    (p, q, r, s) = generate_primes()
    N = p * q * r * s
    e = 0x10001

    with open("flag.txt", "r") as flag_file:
        flag = flag_file.read().strip()

    CT = pow(bytes_to_long(flag.encode()), e, N)

    print(f"{N = }")
    print(f"{CT = }")


    return 0

if __name__ == '__main__':
    raise SystemExit(main())
# N = 489654925303072532553659432557377999607856370197579144782976005904927235244321459117898721690940319487769632950077647476152880207627385231603017537961906244964117707813500615680799967895028255666319186794462243666159201392490299439947399915406223652423977002396844720487588735149486903743362109592536081726574342051928022071576485169655694281378301551060632699138055044915993078059902577590451519251321215765308977494770310317350866241246677761542212605478044672014913289740381478940929584556588858045439572693806615268502627912952686133840081188641597461343817750411035667135310831687533531094008308185320371643348451
# CT = 58535947031303233853656030097871859886777764034955095086618901763996192727846608049414977429851683454541344096765319691912454768331685486037922533236779909508856486986528041125267338846421238077083738092020495236946742989769815669001100361743526446503248639704900983287986142636083524250650662602975802778548032518674346903013262799229594298599457623347987250272218522320743415393958131916181915804368140008312975210397791293701839101635851486434802271100141743496402698229558250485987421664294229816166263965806962242894230766553316312608696594536239328785792283453559549564751529321240567418095487324718881437825650
```

### Solution ###

Looking at the problem code, we easy to construct the polynomial of N that have the variable is p. So we can find the root of this polynomial to get the value of p. After that, we can easily calculate the value of q, r, s and the flag.Here is my sol code in sagemath:

```python
from sage.all import IntegerRing, ZZ
from Crypto.Util.number import *
N = 489654925303072532553659432557377999607856370197579144782976005904927235244321459117898721690940319487769632950077647476152880207627385231603017537961906244964117707813500615680799967895028255666319186794462243666159201392490299439947399915406223652423977002396844720487588735149486903743362109592536081726574342051928022071576485169655694281378301551060632699138055044915993078059902577590451519251321215765308977494770310317350866241246677761542212605478044672014913289740381478940929584556588858045439572693806615268502627912952686133840081188641597461343817750411035667135310831687533531094008308185320371643348451
CT = 58535947031303233853656030097871859886777764034955095086618901763996192727846608049414977429851683454541344096765319691912454768331685486037922533236779909508856486986528041125267338846421238077083738092020495236946742989769815669001100361743526446503248639704900983287986142636083524250650662602975802778548032518674346903013262799229594298599457623347987250272218522320743415393958131916181915804368140008312975210397791293701839101635851486434802271100141743496402698229558250485987421664294229816166263965806962242894230766553316312608696594536239328785792283453559549564751529321240567418095487324718881437825650

Z = PolynomialRing(ZZ, "x")
x = Z.gen()

f = x*(2*x+1)*(2*(2*x+1)+1)*(2*(2*(2*x+1)+1)+1) - N
p = f.roots()[0][0]
p = int(p)
assert N - p*(2*p + 1)*(2*(2*p + 1) + 1)*(2*(2*(2*p + 1) + 1) + 1) == 0
phi = (p-1)*2*p*2*(2*p+ 1)*2*(2*(2*p + 1) + 1)

e = 0x10001

d = inverse(e, phi)

PT = pow(CT, d, N)
print(long_to_bytes(int(PT)))

# gctf{54dly_50ph13_63rm41n_pr1m35_wh3r3_n07_u53d_53curly}
```

## 2. AES Overdrive ##

### Problem code ###

```python
#!/usr/bin/env python3
import os
from typing import List
from Crypto.Util.Padding import pad, unpad
import aes

NORMAL_ROUNDS = 22
PREMIUM_ROUNDS = 24
PREMIUM_USER = b"premium"


def expand_key(key: bytes, rounds: int) -> List[List[int]]:
    round_keys = [[key[i:i + 4] for i in range(0, len(key), 4)]]
    while len(round_keys) < rounds + 1:
        base_key = b"".join(round_keys[-1])
        round_keys += aes.expand_key(base_key, 10)[1:]
    round_keys = [b"".join(k) for k in round_keys]
    round_keys = [aes.bytes2matrix(k) for k in round_keys]
    return round_keys[:rounds + 1]


def encrypt_block(pt: bytes, key: bytes, rounds: int) -> bytes:
    if len(pt) != 16 or len(key) != 16:
        raise ValueError("Invalid input length")

    subkeys = expand_key(key, rounds)
    assert len(subkeys) == rounds + 1

    block = aes.bytes2matrix(pt)
    aes.add_round_key(block, subkeys[0])

    for i in range(1, rounds+1):
        aes.sub_bytes(block)
        aes.shift_rows(block)
        aes.mix_columns(block)
        aes.add_round_key(block, subkeys[i])

    return aes.matrix2bytes(block)


def decrypt_block(ct: bytes, key: bytes, rounds: int) -> bytes:
    if len(ct) != 16 or len(key) != 16:
        raise ValueError("Invalid input length")

    subkeys = expand_key(key, rounds)[::-1]
    assert len(subkeys) == rounds + 1

    block = aes.bytes2matrix(ct)

    for i in range(rounds):
        aes.add_round_key(block, subkeys[i])
        aes.inv_mix_columns(block)
        aes.inv_shift_rows(block)
        aes.inv_sub_bytes(block)

    aes.add_round_key(block, subkeys[-1])

    return aes.matrix2bytes(block)


def encrypt_msg(pt: str, key: bytes, premium: bool) -> str:
    pt_bytes = pad(pt.encode(), 16)
    pt_blocks = [pt_bytes[i:i + 16] for i in range(0, len(pt_bytes), 16)]

    for block in pt_blocks[1:]:
        if block.startswith(PREMIUM_USER):
            raise ValueError("Invalid plaintext")

    if len(pt_blocks) > 3:
        raise ValueError("Message too long")

    rounds = PREMIUM_ROUNDS if premium else NORMAL_ROUNDS
    ct = b"".join([encrypt_block(block, key, rounds) for block in pt_blocks])
    return ct.hex()


def decrypt_msg(ct: str, key: bytes, premium: bool) -> str:
    ct_bytes = bytes.fromhex(ct)
    ct_blocks = [ct_bytes[i:i + 16] for i in range(0, len(ct_bytes), 16)]

    if len(ct_blocks) > 3:
        raise ValueError("Ciphertext too long")

    rounds = PREMIUM_ROUNDS if premium else NORMAL_ROUNDS
    pt = b"".join([decrypt_block(block, key, rounds) for block in ct_blocks])
    return unpad(pt, 16).decode()


def main():
    key = os.urandom(16)
    attempts = 0
    max_attempts = 3

    while attempts <= max_attempts:
        option = input(
            "Enter option (1: Encrypt, 2: Premium Encrypt, 3: Guess Key): ")

        if option == "1":
            pt = input("Enter plaintext: ")
            if pt == PREMIUM_USER.decode():
                print("Not so fast my friend.")
                return
            ct = encrypt_msg(pt, key, False)
            print(f"Ciphertext: {ct}")

        elif option == "2":
            ct = input("Enter ciphertext: ")
            try:
                if decrypt_msg(ct, key, False) != PREMIUM_USER.decode():
                    print("Sorry, you are not a premium user.")
                    return
            except Exception:
                print("Error")
                return

            pt = input("Enter plaintext: ")
            ct = encrypt_msg(pt, key, True)
            print(f"Ciphertext: {ct}")

        elif option == "3":
            key_guess = input("Enter key (hex): ")
            try:
                key_guess = bytes.fromhex(key_guess)
                if key_guess == key:
                    print("Correct key!")
                    with open('/app/flag.txt', 'r') as flag:
                        print(f"Flag: {flag.read().strip()}")
                    return
                else:
                    print("Incorrect key.")
            except ValueError:
                print("Invalid key format. Please enter a valid hex string.")

        else:
            print("Invalid option. Please choose 1, 2, or 3.")

        attempts += 1

    print("Maximum attempts reached. See you later!")


if __name__ == "__main__":
    main()
```

### Solution ###

So in this challenge we have to bypass 2 things. First we have to obtain the ciphertext of "premium" so notice that the checker in encrypt_msg function not check the first block of plaintext so we just send the pad("premium",16) to get the ciphertext of "premium". After bypass that we can access the premium encrypt oracle that encrypt with 24 round . So just send the same message as 22 round encryption we can reduce this AES to 1-round AES.
For the technique and function i use in this master key recovery function: 

- [AES-128 Master Key Recovery from 1 Round](https://github.com/fanosta/aeskeyschedule)
- [Section 4 in this paper](https://eprint.iacr.org/2010/633.pdf)

Here is my sol code:

```python
import os
from typing import List
from Crypto.Util.Padding import pad, unpad
import aes
from aeskeyschedule import reverse_key_schedule
from itertools import product
from pwn import *
HOST = "challs.glacierctf.com"
PORT = 13374

NORMAL_ROUNDS = 22
PREMIUM_ROUNDS = 24
PREMIUM_USER = b"premium"

def expand_key(key: bytes, rounds: int) -> List[List[int]]:
    round_keys = [[key[i:i + 4] for i in range(0, len(key), 4)]]
    while len(round_keys) < rounds + 1:
        base_key = b"".join(round_keys[-1])
        round_keys += aes.expand_key(base_key, 10)[1:]
    round_keys = [b"".join(k) for k in round_keys]
    round_keys = [aes.bytes2matrix(k) for k in round_keys]
    return round_keys[:rounds + 1]



def encrypt_block(pt: bytes, key: bytes, rounds: int) -> bytes:
    if len(pt) != 16 or len(key) != 16:
        raise ValueError("Invalid input length")

    subkeys = expand_key(key, rounds)
    assert len(subkeys) == rounds + 1

    block = aes.bytes2matrix(pt)
    aes.add_round_key(block, subkeys[0])

    for i in range(1, rounds+1):
        aes.sub_bytes(block)
        aes.shift_rows(block)
        aes.mix_columns(block)
        aes.add_round_key(block, subkeys[i])

    return aes.matrix2bytes(block)


def decrypt_block(ct: bytes, key: bytes, rounds: int) -> bytes:
    if len(ct) != 16 or len(key) != 16:
        raise ValueError("Invalid input length")

    subkeys = expand_key(key, rounds)[::-1]
    assert len(subkeys) == rounds + 1

    block = aes.bytes2matrix(ct)

    for i in range(rounds):
        aes.add_round_key(block, subkeys[i])
        aes.inv_mix_columns(block)
        aes.inv_shift_rows(block)
        aes.inv_sub_bytes(block)

    aes.add_round_key(block, subkeys[-1])

    return aes.matrix2bytes(block)


def encrypt_msg(pt: str, key: bytes, premium: bool) -> str:
    pt_bytes = pad(pt.encode(), 16)
    pt_blocks = [pt_bytes[i:i + 16] for i in range(0, len(pt_bytes), 16)]

    for block in pt_blocks[1:]:
        if block.startswith(PREMIUM_USER):
            raise ValueError("Invalid plaintext")

    if len(pt_blocks) > 3:
        raise ValueError("Message too long")

    rounds = PREMIUM_ROUNDS if premium else NORMAL_ROUNDS
    ct = b"".join([encrypt_block(block, key, rounds) for block in pt_blocks])
    return ct.hex()


def decrypt_msg(ct: str, key: bytes, premium: bool) -> str:
    ct_bytes = bytes.fromhex(ct)
    ct_blocks = [ct_bytes[i:i + 16] for i in range(0, len(ct_bytes), 16)]

    if len(ct_blocks) > 3:
        raise ValueError("Ciphertext too long")

    rounds = PREMIUM_ROUNDS if premium else NORMAL_ROUNDS
    pt = b"".join([decrypt_block(block, key, rounds) for block in ct_blocks])
    return unpad(pt, 16).decode()
import time
def recover_key(ct_differ_inv, pt_differ, pt1, pt2):
    key_pair = []
    for i in range(16):
        pair = []
        for key in range(256):
            pt_a = key^pt1[i]
            pt_b = key^pt2[i]
            if(pt_a^pt_b != pt_differ[i]):
                continue
            ct_a = aes.s_box[pt_a]
            ct_b = aes.s_box[pt_b]
            if ct_differ_inv[i] == ct_a^ct_b:
                pair.append(key)
        key_pair.append(pair)
    return key_pair
     

def main():
    r = remote(HOST, PORT, level='debug')
    
    # Option 1: Encrypt "premium" with tabs
    r.recvuntil(b"Enter option (1: Encrypt, 2: Premium Encrypt, 3: Guess Key): ")
    r.sendline(b"1")
    r.sendlineafter(b"Enter plaintext: ", b'premium\t\t\t\t\t\t\t\t\t')
    ct = r.recvline().decode()
    ct1 = ct.split("Ciphertext: ")[1][:-1]
    assert len(ct1) == 64
    print("ct1:", ct1)

    # Option 2: Send ciphertext and known plaintext
    r.sendline(b"2")
    r.sendlineafter(b"Enter ciphertext: ", bytes.fromhex(ct1[:32]).hex().encode())
    to_send = b'premium\t\t\t\t\t\t\t\t\t'
    r.sendlineafter(b"Enter plaintext: ", to_send)
    ct = r.recvline().decode()
    ct2 = ct.split("Ciphertext: ")[1][:-1]
    print("ct:", ct2)
    assert len(ct2) == 64

    # Process the ciphertexts
    pt1 = bytes.fromhex(ct1[:32])
    pt2 = bytes.fromhex(ct1[32:])
    ct1_block = bytes.fromhex(ct2[:32])
    ct2_block = bytes.fromhex(ct2[32:])

    # Convert to matrix and apply AES operations
    pt1_matrix = aes.bytes2matrix(pt1)
    pt2_matrix = aes.bytes2matrix(pt2)
    
    aes.sub_bytes(pt1_matrix)
    aes.sub_bytes(pt2_matrix)
    aes.shift_rows(pt1_matrix)
    aes.shift_rows(pt2_matrix)
    aes.mix_columns(pt1_matrix)
    aes.mix_columns(pt2_matrix)
    
    pt1_processed = aes.matrix2bytes(pt1_matrix)
    pt2_processed = aes.matrix2bytes(pt2_matrix)

    # Calculate differences
    pt_differ = xor(pt1_processed, pt2_processed)
    ct_differ = xor(ct1_block, ct2_block)
    
    ct_differ_matrix = aes.bytes2matrix(ct_differ)
    pt_differ_matrix = aes.bytes2matrix(pt_differ)
    
    aes.inv_mix_columns(ct_differ_matrix)
    aes.inv_shift_rows(ct_differ_matrix)
    
    ct_differ_processed = aes.matrix2bytes(ct_differ_matrix)
    pt_differ_processed = aes.matrix2bytes(pt_differ_matrix)

    # Recover the keys
    keypair = recover_key(ct_differ_processed, pt_differ_processed, pt1_processed, pt2_processed)
    combinations = product(*keypair)
    
     
    count = 0
    for key in combinations:
        key = bytes(key)
        print("count:", count)
        count += 1
        base_key = reverse_key_schedule(key,3)
        base_key = reverse_key_schedule(base_key,10)
        base_key = reverse_key_schedule(base_key,10)
        try:
            print(decrypt_msg(ct1, base_key, False))
            
        except:
            continue
        print("check")
        r.sendline(b"3")
        r.recvuntil(b"Enter key (hex): ")
        r.sendline(base_key.hex().encode())
        print(r.readline())
        break

if __name__ == "__main__":
    main()
```

