---
layout: post
title: Writeups for ImaginaryCTF 2024
description: Some crypto challenge writeups.
date: '2024-04-23 10:43:00 +0700'
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---

## <span style="color: orange;">Base64</span>

### Description
yet another base64 decoding challenge
```python
from Crypto.Util.number import bytes_to_long

q = 64

flag = open("flag.txt", "rb").read()
flag_int = bytes_to_long(flag)

secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

print(f"{secret_key = }")

```

Output :
```text
secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

```
### Solution

This is just a base conversion. Reverse from the last element of the array to retrieve the original number.

```python
secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

secret_key = secret_key[::-1][1:]
from Crypto.Util.number import long_to_bytes
k = 1
for i in secret_key:
    k = 64*k + i
print(long_to_bytes(k))
```
FLAG : **ictf{b4se_c0nv3rs1on_ftw_236680982d9e8449}**

## <span style="color: orange;">Integrity</span>

### Description 
I think this is how signing works

```python
from Crypto.Util.number import *
from binascii import crc_hqx

p = getPrime(1024)
q = getPrime(1024)

n = p*q
e = 65537
tot = (p-1)*(q-1)
d = pow(e, -1, tot)

flag = bytes_to_long(open("flag.txt", "rb").read())
ct = pow(flag, e, n)

#signature = pow(flag, d, n) # no, im not gonna do that
signature = pow(flag, crc_hqx(long_to_bytes(d), 42), n)

print(f"{n = }")
print(f"{ct = }")
print(f"{signature = }")
```

Output:
```text
n =         10564138776494961592014999649037456550575382342808603854749436027195501416732462075688995673939606183123561300630136824493064895936898026009104455605012656112227514866064565891419378050994219942479391748895230609700734689313646635542548646360048189895973084184133523557171393285803689091414097848899969143402526024074373298517865298596472709363144493360685098579242747286374667924925824418993057439374115204031395552316508548814416927671149296240291698782267318342722947218349127747750102113632548814928601458613079803549610741586798881477552743114563683288557678332273321812700473448697037721641398720563971130513427
ct =        5685838967285159794461558605064371935808577614537313517284872621759307511347345423871842021807700909863051421914284950799996213898176050217224786145143140975344971261417973880450295037249939267766501584938352751867637557804915469126317036843468486184370942095487311164578774645833237405496719950503828620690989386907444502047313980230616203027489995981547158652987398852111476068995568458186611338656551345081778531948372680570310816660042320141526741353831184185543912246698661338162113076490444675190068440073174561918199812094602565237320537343578057719268260605714741395310334777911253328561527664394607785811735
signature = 1275844821761484983821340844185575393419792337993640612766980471786977428905226540853335720384123385452029977656072418163973282187758615881752669563780394774633730989087558776171213164303749873793794423254467399925071664163215290516803252776553092090878851242467651143197066297392861056333834850421091466941338571527809879833005764896187139966615733057849199417410243212949781433565368562991243818187206912462908282367755241374542822443478131348101833178421826523712810049110209083887706516764828471192354631913614281317137232427617291828563280573927573115346417103439835614082100305586578385614623425362545483289428
```
### Solution

In this challenge we have to find the plaintext since it encrypt with public key and then instead of using private key to decrypt it use the CRC checksum. First brute force the crc checksum since the challenge code uses [CRC-16-CCITT](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) so the checksum is brute-able by add the exponent e to signature modulo equation:
```python
for i in range(40000):
    if pow(signature,e,n) == pow(ct,i,n):
        print(i)
        break
# output = 30359
```
After retrive the CRC checksum we can calculate the plain text by solving following system of modulo equations: 

m^65537 ≡ ct (mod n)
m^30359 ≡ signature (mod n)

FLAG: **ictf{oops_i_leaked_some_info}**

## <span style="color: orange;">Tango</span>

### Description

Let's dance!

```python
from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32

from secret import FLAG

KEY = token_bytes(32)


def encrypt_command(command):
    if len(command) != 3:
        print('Nuh uh.')
        return
    cipher = Salsa20.new(key=KEY)
    nonce = cipher.nonce
    data = json.dumps({'user': 'user', 'command': command, 'nonce': token_hex(8)}).encode('ascii')
    checksum = long_to_bytes(crc32(data))
    ciphertext = cipher.encrypt(data)
    print('Your encrypted packet is:', (nonce + checksum + ciphertext).hex())


def run_command(packet):
    packet = bytes.fromhex(packet)
    nonce = packet[:8]
    checksum = bytes_to_long(packet[8:12])
    ciphertext = packet[12:]

    try:
        cipher = Salsa20.new(key=KEY, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        if crc32(plaintext) != checksum:
            print('Invalid checksum. Aborting!')
            return

        data = json.loads(plaintext.decode('ascii'))
        user = data.get('user', 'anon')
        command = data.get('command', 'nop')

        if command == 'nop':
            print('...')
        elif command == 'sts':
            if user not in ['user', 'root']:
                print('o_O')
                return
            print('The server is up and running.')
        elif command == 'flag':
            if user != 'root':
                print('You wish :p')
            else:
                print(FLAG)
        else:
            print('Unknown command.')
    except (json.JSONDecodeError, UnicodeDecodeError):
        print('Invalid data. Aborting!')


def menu():
    print('[E]ncrypt a command')
    print('[R]un a command')
    print('[Q]uit')


def main():
    print('Welcome to the Tango server! What would you like to do?')
    while True:
        menu()
        option = input('> ').upper()
        if option == 'E':
            command = input('Your command: ')
            encrypt_command(command)
        elif option == 'R':
            packet = input('Your encrypted packet (hex): ')
            run_command(packet)
        elif option == 'Q':
            exit(0)
        else:
            print('Unknown option:', option)


if __name__ == '__main__':
    main()
```

### Solution

Salsa 20 is the stream cipher with generate keystream and then xor with ciphertext to generate the corresponding plaintext. In this challenge we need to bitflipping the ciphertext in order to change the plaintext so it can satisfied the condition to obtain the flag and calculate the checksum of the command we send to the server. 
First encrypt 1 sample command and retrieve the keystream then generate correspoding ciphertext to bitflipping the plaintext. 
Then we need to calculate the checksum of the plaintext. A little trick here is the server accept the packet with no nonce key. So just send **{'user': 'user', 'command': command}** so we can calculate it CRC32 checksum ourself: 

```python
import json
from Crypto.Util.number import *
from binascii import crc32
k = '8da910e05a5098aaf1b8acae23771f29d7e5f46743288d2d3ad38c7f76b26e6f3ac419777c8ca5d81b5555bd90f7584a8a39b0c3c478a8ad6dcec8946d49b51876edf5cb01f8cb1cdd15de'
k = bytes.fromhex(k)
 
nonce = k[:8]
checksum = k[8:12]
ciphertext = k[12:]


meme = b'{"user": "user", "command": "mem", "nonce": "kkk"}'
lolo = meme[:35]
keystream = bytes(a^b for a,b in zip(lolo,ciphertext[:35]))
check = b'{"user": "root", "command": "flag"}'
print(len(check))
new_ciphertext = bytes(a^b for a,b in zip(keystream,check))
print(bytes(a^b for a,b in zip(new_ciphertext,keystream)))
 
checksum = long_to_bytes(crc32(check))
nonce = nonce
print((nonce + checksum + new_ciphertext).hex())

```
FLAG = **ictf{F0xtr0t_L1m4_4lph4_G0lf}**

## <span style="color: orange;">Solitute</span>
### Description

The best thinking has been done in solitude. The worst has been done in turmoil.

```python
import random

def xor(a: bytes, b: bytes):
  out = []
  for m,n in zip(a,b):
    out.append(m^n)
  return bytes(out)

class RNG():
  def __init__(self, size, state=None):
    self.size = size
    self.state = list(range(self.size+2))
    random.shuffle(self.state)
  def next(self):
    idx = self.state.index(self.size)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size)
    if self.state[0] == self.size:
      self.state.pop(0)
      self.state.insert(1, self.size)
    idx = self.state.index(self.size+1)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size+1)
    if self.state[0] == self.size+1:
      self.state.pop(0)
      self.state.insert(1, self.size+1)
    if self.state[1] == self.size+1:
      self.state.pop(1)
      self.state.insert(2, self.size+1)
    c1 = self.state.index(self.size)
    c2 = self.state.index(self.size+1)
    self.state = self.state[max(c1,c2)+1:] + [self.size if c1<c2 else self.size+1] + self.state[min(c1,c2)+1:max(c1,c2)] + [self.size if c1>c2 else self.size+1] + self.state[:min(c1,c2)]
    count = self.state[-1]
    if count in [self.size,self.size+1]:
      count = self.size
    self.state = self.state[count:-1] + self.state[:count] + self.state[-1:]
    idx = self.state[0]
    if idx in [self.size,self.size+1]:
      idx = self.size
    out = self.state[idx]
    if out in [self.size,self.size+1]:
      out = self.next()
    return out

if __name__ == "__main__":
  flag = open("flag.txt", "rb").read()
  while True:
    i = int(input("got flag? "))
    for _ in range(i):
      rng = RNG(128)
      stream = bytes([rng.next() for _ in range(len(flag))])
      print(xor(flag, stream).hex())
```

### Solution

In this challenge we have a custom RNG which generate a random keystream and then xor with flag. After analizing the sample keystreams i realized that for about 20000 keystreams the number that appear most at every index of keystream is 0. So just obtain 20000 ciphertext and then find the most ASCII character that appear the most at each index so we can recover the flag:

```python
from collections import Counter
from Crypto.Util.number import long_to_bytes

with open("flag1.txt", "r") as f:
    lines = f.readlines()

a1 = [a.strip() for a in lines]
b = [bytes.fromhex(a) for a in a1]
charset = b'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*(_){}'
for idx in range(33):
    posible = []
    count = []




    for i in b:
        byte_value = long_to_bytes(i[idx])
        if byte_value in charset and byte_value not in posible:
            posible.append(byte_value)
            count.append(0)
        if byte_value in posible:
            count[posible.index(byte_value)] += 1

    
    if count:
        max_count_index = count.index(max(count))
        print(posible[max_count_index].decode(),end ="")
    else:
        print("No valid entries found.")
```
FLAG : **ictf{biased_rng_so_sad_6b065f93}**








