---
layout: post
title: Writeups for Lake CTF Qual 2024
description: Some crypto challenge writeups.
date: '2024-12-09 10:55:00 +0700'
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---


In this ctf, i solved 3 out of 5 challenges (cuz i am so busy with my final exam). Hope you enjoy this ctf writeups.

## Wild Signature ##

**Problem**:

```python
#!/usr/bin/env python3
import os

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

flag = os.environ.get("FLAG", "EPFL{test_flag}")

msgs = [
    b"I, gallileo, command you to give me the flag",
    b"Really, give me the flag",
    b"can I haz flagg",
    b"flag plz"
]

leos_key = ECC.generate(curve='ed25519')
sigs = [ leos_key.public_key().export_key(format='raw') + eddsa.new(leos_key, 'rfc8032').sign(msg) for msg in msgs]

def parse_and_vfy_sig(sig: bytes, msg: bytes):
    pk_bytes = sig[:32]
    sig_bytes = sig[32:]
    
    pk = eddsa.import_public_key(encoded=pk_bytes)

    if pk.pointQ.x == 0:
        print("you think you are funny")
        raise ValueError("funny user")

    eddsa.new(pk, 'rfc8032').verify(msg, sig_bytes)

if __name__ == "__main__":
    try:
        print("if you really are leo, give me public keys that can verify these signatures")
        for msg, sig in zip(msgs, sigs):
            print(sig[64:].hex())
            user_msg = bytes.fromhex(input())

            # first 64 bytes encode the public key
            if len(user_msg) > 64 or len(user_msg) == 0:
                print("you're talking too much, or too little")
                exit()

            to_verif = user_msg + sig[len(user_msg):]

            parse_and_vfy_sig(to_verif, msg)
            print("it's valid")

    except ValueError as e:
        print(e)
        exit()

    print(flag)

```

**Solution**:

In this chal, we have to send the right public key to the verify function to get the flag. But there are two points to exploit in this chal:

- First, we can send only 1 byte of public key cuz the program will send the remaining bytes of the signature to us.

- Second, every messages are signed with the same key, so we just manage to guess the first byte of the public key and we can get the flag.

```python
import pwn
from Crypto.Util.number import long_to_bytes    
HOST = "chall.polygl0ts.ch"
PORT = 9001
count = 0
while True:
    try:
        print("count: ", count)
        r = pwn.remote(HOST, PORT, level = "debug")

        r.recvuntil(b'signatures\n')
    
        for i in range(4):
            k = r.readline()
            r.sendline("af")
            print(r.readline())
        k = r.readline()
        if k.startswith(b'EPFL{'):
            print(k)
            break
        r.close()
    except EOFError:
        count += 1
        r.close()
        continue

# EPFL{wH4T_d0_yOu_m34n_4_W1LdC4Rd}

```

## Circuit ##

**Problem**:

```python
from Crypto.Random import random
import os
B = 12
def and_gate(a, b):
    return a & b
def or_gate(a, b):
    return a | b
def xor_gate(a, b):
    return a ^ b
def not_gate(a, x):
    return ~a & 1

def rand_circuit(size: int, input_size: int, output_size):
    circ_gates = [or_gate, not_gate, xor_gate, and_gate]
    assert size > 0 and input_size > 0 and output_size > 0
    assert output_size + size <= input_size and (input_size - output_size) % size == 0
    dec = (input_size - output_size) // size
    gates = []
    for iteration in range(1, size + 1):
        gate_level = []
        c_size = input_size - dec * iteration
        for i in range(c_size):
            gate_level.append(
                (random.choice(circ_gates),
                 (i,
                  random.randint(0, c_size + dec - 1))))
        gates.append(gate_level)
    return gates


def eval_circuit(gates, inp):
    assert len(gates) >= 1
    for level in gates:
        new_inp = []
        for gate, (i1, i2) in level:
            new_inp.append(gate(inp[i1], inp[i2]))
        inp = new_inp
    return inp


def i2b(i):
    return list(map(int, bin(i)[2:].zfill(B)))


def b2i(b):
    return int(''.join(map(str, b)), 2)

SIZE = int(input("What circuit size are you interested in ?"))
assert 3 <= SIZE <= B - 1
correct = 0
b = random.getrandbits(1)
p = rand_circuit(SIZE, B, B - SIZE)
keys = set()
while correct < 32:
    input_func = random.getrandbits(B)
    choice = int(input(f"[1] check bit\n[2] test input\n"))
    if choice == 1:
        assert int(input("bit: ")) == b
        b = random.getrandbits(1)
        p = rand_circuit(SIZE, B, B - SIZE)
        keys = set()
        correct += 1
    else:
        i = int(input(f"input: "))
        if i in keys or len(keys) > 7 or not 0 <= i <= 2 ** B:
            print("uh uh no cheating")
            exit()
        keys.add(i)
        if b == 0:
            res = random.getrandbits(B - SIZE)
        else:
            res = b2i(eval_circuit(p, i2b(i)))

        print(f"res = {res}")
print("well done !!")
print(os.getenv("flag",b"EPFL{fake_flag}"))

```

**Solution**:

- So in this chal, we have to guess the right b 32 times with generate with python random library ( which is 1 or 0). The first option to guess b and the second option to help us analyze what is b. observe that if b is 0, then res is generate by random library which is no bias and otherwise. So we just need to send 7 numbers to option 2 and then analyze the bias. I choose Size = 6 and the evaluate function help me to decide which value is higher chance to be b. The author just let us send 7 times so just run the program until we lucky enough to get the flag. (the code took me about 3 minutes to run).

```python
import pwn
from Crypto.Util.number import long_to_bytes, bytes_to_long



def i2b(i):
    return list(map(int, bin(i)[2:].zfill(B)))


def b2i(b):
    return int(''.join(map(str, b)), 2)
def evaluate(list):
    if 7 in list:
        return 1
    if sum(list) < 15:
        return 1
    return 0
while True:
    try:
        HOST = "chall.polygl0ts.ch"
        PORT = 9068
        B = 12
        r = pwn.remote(HOST, PORT)

        r.sendlineafter("What circuit size are you interested in ?", "6")
        for i in range(32):
            r.sendlineafter("[1] check bit\n[2] test input\n", "2")
            count = [0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            for j in range(7):
                r.sendlineafter("input: ", str(j))
                k = r.readline().decode().strip().split(" ")[-1]
                k = int(k)
                k = i2b(k)
                for idx,l in enumerate(k):
                    if l == 1:
                        count[idx] += 1
                if(j != 6):
                   r.sendlineafter("[1] check bit\n[2] test input\n", "2")
            print("count",count)

            guess = evaluate(count)
            r.sendlineafter("[1] check bit\n[2] test input\n", "1")
            r.sendlineafter("bit: ", str(guess))
        print(r.readline())
        print(r.readline())
        exit()
    except EOFError:
        r.close()
        continue
# EPFL{r4nd0m_c1rcu1t5_4r3_n0_g00d_rngs??}
```

## Cert ##

**Problem**:

We're given 2 file in this chal:

- cert.py:

```python
from binascii import hexlify, unhexlify
from Crypto.Util.number import bytes_to_long, long_to_bytes
from precomputed import message, signature, N, e
from flag import flag


if __name__ == "__main__":
    print(message + hexlify(long_to_bytes(signature)).decode())
    cert = input(" > ")
    try: 
        s = bytes_to_long(unhexlify(cert))
        assert(s < N)
        if pow(s,e,N)==bytes_to_long("admin".encode()):
            print(flag)
        else:
            print("Not admin")
    except:
        print("Not admin")
```

- precomputed.py:

```python
from Crypto.Util.number import bytes_to_long

message = "Sign \"admin\" for flag. Cheers, "
m = 147375778215096992303698953296971440676323238260974337233541805023476001824
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581339496966919577443709945261868529023522932989623577005570770318555545829416559256628409790858255069196868638535981579544864087110789571665244161
e = 65537
signature = 20661001899082038314677406680643845704517079727331364133442054045393583514677972720637608461085964711216045721340073161354294542882374724777349428076118583374204393298507730977308343378120231535513191849991112740159641542630971203726024554641972313611321807388512576263009358133517944367899713953992857054626
assert(m == bytes_to_long(message.encode()))

```

**Solution**:

- In this chal, we're given the message, signature, N, e and after compute $$signature^e mod N$$, it not equal to the message so i guess this is fault signarute RSA. Then just use fault attack and recover p then calculate the signature for "admin" and get the flag.

- The idea for recover is here : [David Wong's blog](https://www.cryptologie.net/article/371/fault-attacks-on-rsas-signatures/)

```python
import pwn
from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
m = 147375778215096992303698953296971440676323238260974337233541805023476001824
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581339496966919577443709945261868529023522932989623577005570770318555545829416559256628409790858255069196868638535981579544864087110789571665244161
e = 65537
signature = 20661001899082038314677406680643845704517079727331364133442054045393583514677972720637608461085964711216045721340073161354294542882374724777349428076118583374204393298507730977308343378120231535513191849991112740159641542630971203726024554641972313611321807388512576263009358133517944367899713953992857054626

p = gcd(pow(signature, e, N) - m, N)

q = N // p

d = pow(e, -1, (p - 1) * (q - 1))

r = pwn.remote("chall.polygl0ts.ch",9024)

admin = "admin".encode()

s = pow(bytes_to_long(admin), d, N)

print(r.readline())
r.sendlineafter(" > ", long_to_bytes(s).hex())
print(r.readline())

# EPFL{Fau17Y_5igNs_Ar3_al!_y0U_ne3D}
```

Thank for reading this blog. Hope you enjoy it.
