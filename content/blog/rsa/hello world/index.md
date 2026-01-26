---
title: "PwnMe CTF 2025 Writeup"
date: 2025-03-03
draft: false
description: "Writeup for some challenges that I solved in PwnMe CTF 2025."
tags: ["ctf", "writeup", "Reverse Engineering"]
# series: ["Documentation"]
# series_order: 13
---

## Overview

Here are some of the challenges that I solved during PwnMe CTF 2025:

## Rev
### Back to the past

<!-- ![back_to_the_past_0](writeups/pwnme_ctf_2025/back_to_the_past_0.png) -->
> Using the provided binary and the encrypted file, find a way to retrieve the flag contained in "flag.enc". Note that the binary would have been run in May 2024. Note: The flag is in the format PWNME{...}
>
> Author : `Fayred`
>
> Flag format: `PWNME{.........................}`

We are given a binary executable that encrypts the flag file. 

```bash
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ ./backToThePast
Usage: ./backToThePast <filename>
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ echo 1234 > test
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ ./backToThePast test
time : 1740925301
```

Running the binary, we see that it prints out the current timestamp. So it might use the timestamp for encryption. Let's check that in IDA:

{{< details >}}
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    char v3; // cl
    int v5; // edx
    char v6; // cl
    int v7; // edx
    char v8; // cl
    int v9; // eax
    char v10; // cl
    int v11; // [rsp+1Ch] [rbp-124h]
    unsigned int v12; // [rsp+20h] [rbp-120h]
    __int64 v13; // [rsp+28h] [rbp-118h]
    char v14[264]; // [rsp+30h] [rbp-110h] BYREF
    unsigned __int64 v15; // [rsp+138h] [rbp-8h]

    v15 = __readfsqword(0x28u);
    if ( argc > 1 )
    {
        v12 = time(0LL, argv, envp);
        printf((unsigned int)"time : %ld\n", v12, v5, v6);
        srand(v12);
        v13 = fopen64(argv[1], "rb+");
        if ( v13 )
        {
            while ( 1 )
            {
                v11 = getc(v13);
                if ( v11 == 0xFFFFFFFF )
                {
                    break;
                }

                fseek(v13, 0xFFFFFFFFFFFFFFFFLL, 1LL);
                v9 = rand();
                fputc(v11 ^ (unsigned int)(v9 % 0x7F), v13);
            }

            fclose(v13);
            strcpy(v14, argv[1]);
            strcat(v14, ".enc");
            if ( (unsigned int)rename(argv[1], v14) )
            {
                printf(
                    (unsigned int)"Can't rename %s filename to %s.enc",
                    (unsigned int)argv[1],
                    (unsigned int)argv[1],
                    v10);
                return 1;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            printf((unsigned int)"Can't open file %s\n", (unsigned int)argv[1], v7, v8);
            return 1;
        }
    }
    else
    {
        printf((unsigned int)"Usage: %s <filename>\n", (unsigned int)*argv, (_DWORD)envp, v3);
        return 1;
    }
}
```
{{< /details >}}

Indeed, it uses the timestamp to set seed, then XOR our file with random numbers and write it to a `.enc` file. 

Things should be easy enough. However, when I tried to write a solve script using libc's `random`, it didn't give the right result. After debugging, I noticed that the random numbers of the program were different from mine. So something has been changed 🤔. 

It turns out the `srand` and `rand` functions are not the standard libc functions, but rather custom functions:

```c
__int64 __fastcall srand(int a1)
{
    __int64 result; // rax

    result = (unsigned int)(a1 - 1);
    seed = result;
    return result;
}
```

```c
unsigned __int64 rand()
{
    seed = 0x5851F42D4C957F2DLL * seed + 1;
    return (unsigned __int64)seed >> 0x21;
}
```

The `srand` function actually sets the seed to be equal to `a1 - 1`. I'm not sure if `rand` is different from the standard one, but we'll not care about that.

From this, I wrote a quick script to solve the challenge. Given that the challenge's description said `the binary would have been run in May 2024`, I bruteforced the timestamp from May to June:

```py
data = open("flag.enc", 'rb').read()

seed = 1740845724
def srand(s):
    global seed
    seed = s - 1
def rand():
    global seed
    seed = (0x5851F42D4C957F2D * seed + 1) & 0xffffffffffffffff
    return seed >> 0x21

for t in range(1714521600, 1717200000):
    srand(t)
    msg = []
    for c in data:
        rand_num = rand()
        msg.append(c ^ (rand_num % 0x7f))
    msg = bytes(msg)
    if b"PWNME" in msg:
        print(msg)
```

Running this will give us the flag: `PWNME{4baf3723f62a15f22e86d57130bc40c3}`

### C4 License

<!-- ![c4_license_0](writeups/pwnme_ctf_2025/c4_license_0.png) -->
> Using the license of 'Noa' and the provided binary, develop a keygen to create a valid license for the 100 requested users.
>
> Author : `Fayred`
>
> Flag format: `PWNME{.........................}`
>
> Connect : `nc --ssl [Host] 443`

We are given two files: A binary executable and a sample license for a user named `Noa`. 

Running the binary will show us a form. Typing in an invalid license, we'll get `Invalid license key`. If we use the sample license, we'll get `Congratulation, your license key is valid !`

![c4_license_1](writeups/pwnme_ctf_2025/c4_license_1.png)
![c4_license_2](writeups/pwnme_ctf_2025/c4_license_2.png)

There are a lot of functions, so it might be a good idea to look for the string `Invalid license key` in the file. 

{{< alert "lightbulb" >}}
To find a string in IDA, we can use `Ctrl+F` for IDA 9.0, or `Alt+T` for older versions.
{{< /alert >}}

We can see that it's used in the function `C4License::on_checkKey_clicked`. This function will base64 decrypt our license and get `user` and `serial` from the decrypted JSON string. These will be passed to the `checker` function, which checks the values as follows:

1. First, it uses the `crc32` checksum of `user` (which is `a1`) to set the seed through `srand`. Then, it generates two random numbers to make the key `v26`, which is used as the key for RC4 decryption:
```c
v3 = *((unsigned int *)a1 + 2);
v4 = *a1;
v27 = __readfsqword(0x28u);
v5 = crc32(0LL, v4, v3);
srand(v5);
v6 = rand();
*(_DWORD *)v26 = _byteswap_ulong(rand() % 0xFFFF * (v6 % 0xFFFF));
RC4::RC4((RC4 *)v25, v26);
```
2. After that, it will hex decode the `serial` (`a2`) and RC4 decrypt it using the key above. The result will be stored in `v22` 
```c
RC4::RC4((RC4 *)v25, v26);
QByteArray::fromHex((QByteArray *)&v24, a2);
RC4::decrypt(&v22, v25, &v24);
```
3. Finally, it will compare the SHA1 checksum of `v22` and compare it with `b039d6daea04c40874f80459bff40142bd25b995`. 

The hash is not crackable, but through debugging using the sample license, we see that `v22` is `PwNmE_c4_message!137`.

From this, we can write a script that takes 100 username from the server and generate the licenses:

{{<details title="Show solve script">}}
```py
from base64 import b64encode, b64decode
from Crypto.Cipher import ARC4
from ctypes import CDLL
from zlib import crc32
from pwn import *
import time

libc = CDLL("libc.so.6")

def gen_license(username):
    username = username.encode()
    seed = crc32(username)
    print(hex(seed))
    libc.srand(seed)
    
    n1 = libc.rand()
    n2 = libc.rand()
    n = (n1 % 0xffff) * (n2 % 0xffff)
    
    print(hex(n))
    rc4_key = bytes.fromhex(hex(n).replace("0x", '').zfill(8))
    print("key:" , rc4_key.hex())
    
    rc4 = ARC4.new(rc4_key)
    enc = rc4.encrypt(b"PwNmE_c4_message!137")
    
    password = enc.hex()
    
    license = f'{{"user":"{username.decode()}","serial":"{password}"}}'
    print(license)
    
    return b64encode(license.encode()).decode()
    
# print(gen_license("Noa").decode())
p = remote("c4license-90c9d36428b43675.deploy.phreaks.fr", 443, ssl=True)
# context.log_level = 'debug'

for i in range(100):
    msg = p.recvuntil(b"user :").decode()
    print(msg)
    username = msg.split("Your license for ")[1].split(" user")[0].strip()
    print(username)
    license = gen_license(username)
    p.sendline(license.encode())
    time.sleep(0.5)
p.interactive()
```
{{</details>}}

### Mimirev

> A new and obscure programming language, MimiLang, has surfaced. It runs on a peculiar interpreter, but something about it feels… off. Dive into its inner workings and figure out what's really going on. Maybe you'll uncover something unexpected.
>
> Author : `Lxt3h`
>
> Flag format: `PWNME{.........................}`

We are given a binary executable which runs the code in a `.mimi` file. Let's look in IDA!

It seems like it's a Golang binary. When analysing a non-stripped Golang or Rust file, the first thing that I do is looking for interesting function names:

![mimirev_1](writeups/pwnme_ctf_2025/mimirev_1.png)

Well look at that, there is a `github_com_Lexterl33t_mimicompiler_vm_decryptFlag` function. And it's used by `github_com_Lexterl33t_mimicompiler_vm__ptr_VM_VerifyProof`. 

Analysing the function, we see that the function does the following:

1. It pops two values `x` and `y` from the stack and checks some constraints:
```c
x + y == 314159
(x * x + y * y * y - x * y) % 1048573 == 273262
```
2. If `x` and `y` satisfy the constraints, they will be formatted as `%d:%d`. Then the function takes the SHA256 sum of this to decrypt the flag using `github_com_Lexterl33t_mimicompiler_vm_decryptFlag`:

```c
v30 = runtime_convT64(x, v24, v25, 1, 1, v26, v27, v28, v29, v69);
*(_QWORD *)&v93 = "\b";
*((_QWORD *)&v93 + 1) = v30;
v36 = runtime_convT64(y, v24, v31, 1, 1, v32, v33, v34, v35, v70);
*(_QWORD *)&v94 = "\b";
*((_QWORD *)&v94 + 1) = v36;
v41 = fmt_Sprintf((unsigned int)"%d:%d", 5, (unsigned int)&v93, 2, 2, v37, v38, v39, v40, v71, v76, v79, v84);
v46 = runtime_stringtoslicebyte((unsigned int)&v87, v41, 5, 2, 2, v42, v43, v44, v45, v72, v77, v80);
crypto_sha256_Sum256(v46, v41, v47, 2, 2, v48, v49, v50, v51, v73, v81, v85);
v86[0] = v74;
v86[1] = v82;
v52 = a1[8];
v56 = github_com_Lexterl33t_mimicompiler_vm_decryptFlag(
    (__int64)a1[7],
    (signed __int64)v52,
    (__int64)a1[9],
    (__int64)v86,
    16LL,
    32,
    v53,
    v54,
    v55);
```

I will not try to explain `github_com_Lexterl33t_mimicompiler_vm_decryptFlag` fully, but it seems like the SHA256 checksum is used as the key for AES decryption (the first 16 bytes). So what is being decrypted here? 

We haven't even looked at the main function yet. In the main function, there is a part where it creates a new VM:

```c
v170 = github_com_Lexterl33t_mimicompiler_vm_NewVM(
             v79,
             (_DWORD)v52,
             v80,
             (unsigned int)"mTfYS2+3UoKAO+gueELVdxNc6QDBwKW1t8uN5Dx/HIGvWb7kMtmLoyt6SB0EIw39",
             64,
             (unsigned int)"11466b4b07a438fdba619b86088353976073d790344cbf4dae99512028808ecf",
             64,
             v83,
             v84,
             v125,
             v136,
             v143,
             v149,
             v153,
             v154);
```
Looking at this function, there are some interesting stuffs:

```c
__int64 __golang github_com_Lexterl33t_mimicompiler_vm_NewVM(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 sus_base64,
        int _64,
        __int64 sus_hex,
        __int64 _64__,
        int a8,
        int a9)
{
  // variables ...

  v30 = encoding_base64__ptr_Encoding_DecodeString(
          qword_5A57B8,
          sus_base64,
          _64,
          sus_base64,
          _64,
          sus_hex,
          _64__,
          a8,
          a9);

  // ...

  if ( dword_5C5970 )
  {
    result = runtime_gcWriteBarrier4();
    v23 = a1;
    *v27 = a1;
    v24 = v31;
    v27[1] = v31;
    base64_decrypted = v30;
    v27[2] = v30;
    sus_hex_ = sus_hex;
    v27[3] = sus_hex;
  }
  else
  {
    v23 = a1;
    v24 = v31;
    base64_decrypted = v30;
    sus_hex_ = sus_hex;
  }
  *(_QWORD *)(result + 24) = v23;
  *(_QWORD *)(result + 48) = v24;
  *(_QWORD *)(result + 64) = sus_base64;
  *(_QWORD *)(result + 72) = v28;
  *(_QWORD *)(result + 56) = base64_decrypted;
  *(_QWORD *)(result + 88) = _64__;
  *(_QWORD *)(result + 80) = sus_hex_;
  return result;
}
```

We can see that base64 string is decrypted and stored in `result[7] (result + 56)`. Looking back at `github_com_Lexterl33t_mimicompiler_vm_decryptFlag`, we can see that this is used as the first argument. The hex string isn't used in this function tho, so maybe it's AES ECB.

With the informations that we have, let's try to decrypt the flag! First, we need to find `x` and `y`. We can write a quick script to brute-force the solution:
```py
from hashlib import sha256

for x in range(314159+1):
    y = 314159 - x
    if (x * x + y * y * y - x * y) % 1048573 == 273262:
        key = f"{x}:{y}"
        hash = sha256(key.encode()).hexdigest()
        print(key)
```
```
123456:190703 b9b6c6cd17cdb9bc1ff86179883e65116555b6766df2498281cd331366eae5d3
206712:107447 82bd2f75c8fb42d505bbd5b97b0d110f67f493ff74b16d247abbf34f01276459
```

We get two keys. Trying each key (the first 16 bytes), we can see that the first one gives the flag:

![mimirev_2](writeups/pwnme_ctf_2025/mimirev_2.png)


### Super secure network

I actually did this challenge with my friends `jitensha69` and [severus](https://nguyenthienanh05.github.io/). You can see severus's writeup for this challenge [here](https://nguyenthienanh05.github.io/posts/PwnMeCTFRev2025/#super-secure-network) 

## Misc
### Decode Runner

> Welcome to Decode Runner ! You will receive 100 encoded words. Your goal is to decode them and send back the decoded word. You have 3 seconds to respond to each word. Good luck!
>
> Author : `Offpath`
>
> Flag format: `PWNME{.........................}`
>
> Connect : `nc --ssl [host] 443`

I did this challenge with my friend `KangTheConq`. There are a lot of ciphers used here (about 10 ciphers). Let's walk through each of them:

* **Latin Gibberish Cipher:**
```
hint: what is this charabia ???
cipher: siruosus
```

I asked GPT and it said that `charabia` is `gibberish` in French. Googling `gibberish cipher` returns `Latin Gibberish Cipher`. It basically reverses the word and add some suffix. 

To decrypt this, just remove the last two letters and reverse the string:

```py
def latin_gibberish(s):
    data = s[:-2]
    return data[::-1]
```

* **Wabun code (Japanese Morse):**
```
hint: It looks like Morse code, but ...
cipher: f .- g
```

At first, it seems like this is just Morse code. But when submitting the decoded word, the server saids wrong answer.

So what kind of Morse code is this? Turns out, there is another Morse code type named [Wabun code](https://en.wikipedia.org/wiki/Wabun_code). It encode Japanese words using Morse code. I wrote a dirty script to decrypt this (This might not always return the correct result, but it works lol):

{{<details title="Show script">}}
```py
def wabi_sabi(ciphertext):
    qod6 = {
        # Row 1
        "A":   "--.--",
        "I":   ".-",
        "U":   "..-",
        "E":   "-.---",
        "O":   ".-...",
        "N": ".-.-.",

        # Row 2
        "KA":  ".-..",
        "KI":  "-.-..",
        "KU":  "...-",
        "KE":  "-.--",
        "KO":  "----",

        # Row 3
        "SA":  "-.-.-",
        "SHI": "--.-.",
        "SU":  "---.-",
        "SE":  ".---.",
        "SO":  "---.",

        # # Row 4
        # "ZA":  "-.-.",
        # "ZI":  "-.--",
        # "ZU":  "..--",
        # "ZE":  ".--.",
        # "ZO":  "---.",

        # Row 5
        "TA":  "-.",
        "CHI": "..-.",
        "TSU": ".--.",
        "TE":  ".-.--",
        "TO":  "..-..",

        # # Row 6
        # "DA":  "-.",
        # "DI":  "----",
        # "DU":  "--.-",
        # "DE":  "-..-",
        # "DO":  "--..",

        # Row 7
        "NA":  ".-.",
        "NI":  "-.-.",
        "NU":  "....",
        "NE":  "--.-",
        "NO":  "..--",

        # Row 8
        "HA":  "-...",
        "HI":  "--..-",
        "FU":  "--..",
        "HE":  ".",
        "HO":  "-..",

        # # Row 9
        # "BA":  ".-..-",
        # "BI":  ".-...",
        # "BU":  "..-..",
        # "BE":  "....",
        # "BO":  ".--..",

        # # Row 10
        # "PA":  ".-..-",
        # "PI":  ".-...",
        # "PU":  "..-..",
        # "PE":  "....",
        # "PO":  ".--..",

        # Row 11
        "MA":  "-..-",
        "MI":  "..-.-",
        "MU":  "-",
        "ME":  "-...-",
        "MO":  "-..-.",

        # Row 12
        "YA":  ".--",
        "YU":  "-..--",
        "YO":  "--",
        
        "RA":  "...",
        "RI":  "--.",
        "RU":  "-.--.",
        "RE":  "---",
        "RO":  ".-.-",
        
        "WA":  "-.-",
        "WI":  ".-..-",
        "WE":  ".--..",
        "WO":  ".---",
    }
    
    DICT = {}
    
    for key, value in qod6.items():
        DICT[value] = key
    
    ciphertext = ciphertext.split()
    ans = ''
    for word in ciphertext:
        if '.' in word or '-' in word:
            ans += DICT[word]
        else:
            ans += word
    
    return ans.lower()
```
{{</details>}}

* **First Letter:**
```
cipher: India Golf Uniform Alfa November Oscar Delta Oscar November
```

There isn't a hint for this one. We can solve this by taking the first letter of each word to form a new word:

```py
def first_letter(s):
    s = s.split()
    s = [i[0] for i in s]
    s = "".join(s)
    return s.lower()
```

* **Chord cipher:**
```
hint: Hendrix would have had it...
cipher: x24442 x02220 xx0232 320003 022100 xx0232
```

A quick Google shows that Jimi Hendrix is an American guitarist and songwriter. Moreover, the cipher looks like guitar chord, so this might be `Chord cipher`:

```py
def chord_cipher(ciphertext):
    ciphertext = ciphertext.split()
    dict = {"x02220": 'a', "224442":'b', '032010':'c', 'xx0232':'d', '022100':'e', '133211':'f', '320003':'g', 'x24442':'b', 'x32010':'c'}
    ans = ''
    for i in ciphertext:
        ans += dict.get(i, '?')
    return ans
```
* **Baudot Code**
```
hint: He can't imagine finding himself in CTF 150 years later...
cipher: 01111 11000 00011 10010 00011
```

This looks like Morse code, but each "word" is only 5-digit long. A quick ChatGPT gives [Baudot Code](https://www.dcode.fr/baudot-code):

```
baudot_table = {
    "00000": "null", "00100": " ", "10111": "Q", "10011": "W",
    "00001": "E", "01010": "R", "10000": "T", "10101": "Y",
    "00111": "U", "00110": "I", "11000": "O", "10110": "P",
    "00011": "A", "00101": "S", "01001": "D", "01101": "F",
    "11010": "G", "10100": "H", "01011": "J", "01111": "K",
    "10010": "L", "10001": "Z", "11101": "X", "01110": "C",
    "11110": "V", "11001": "B", "01100": "N", "11100": "M",
    "01000": "CR", "00010": "LF", "11011": "Switch to Digits"
}

def baudot_decode(ciphertext):
    bits = ciphertext.split()
    decoded_text = "".join(baudot_table.get(bit, "?") for bit in bits)
    return decoded_text.lower()
```


* **Trimethius Cipher:**
```
hint: Born in 1462 in Germany...
cipher: rmxksmc
```

Googling the hint gives `Johannes Trithemius`. Googling the cipher gives [Trimethius Cipher](https://www.dcode.fr/trithemius-cipher). 

We can use `Try all shifts (bruteforce)` on dcode and we'll see that offset `+3` gives meaningful words. I wrote a script for this:

```py
def trimethius_decode(ciphertext):
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".lower()
    offset = 3
    
    ans = ""
    
    for i in range(len(ciphertext)):
        idx = ALPHABET.index(ciphertext[i])
        ans += ALPHABET[(idx - offset + len(ALPHABET)) % len(ALPHABET)]
        offset += 1
    
    return ans
```

* **Chuck Norris Unary Code**

```
hint: He can snap his toes, and has already counted to infinity twice ...
cipher: 0 0000 00 000 0 0000 00 00 0 000 00 0 0 00 00 00 0 00 00 0 0 000000 00 000 0 0000 00 0 0 0000000 00 0000 0 00 00 00 0 0 00 0 0 0
```

My friend `KangTheConq` found out that this is Chuck Norris Unary Code, and he writes the decoding script too:

```py
def decode_chuck_norris(unary_code):
    parts = unary_code.split()
    binary_string = ""
    
    for i in range(0, len(parts), 2):
        bit = '1' if parts[i] == '0' else '0'
        binary_string += bit * len(parts[i + 1])
    
    decoded_text = ""
    for i in range(0, len(binary_string), 7):
        decoded_text += chr(int(binary_string[i:i+7], 2))
    return decoded_text
```

* **Shankar Speech Defect**
```
hint: Did you realy see slumdog millionaire ?
cipher: PJWX
```

Googling `slumdog millionaire cipher` gives [Shankar Speech Defect](https://www.dcode.fr/shankar-speech-defect). It's just another substitution cipher:

```py
def slumdog(ciphertext):
    cipheralphabet = 'XWYAZBCDQEFGHIKLMNOPJRSTUV'
    plainalphabet = string.ascii_uppercase
    
    plaintext = ''
    for c in ciphertext:
        if c == ' ':
            p = ' '
        else: p = plainalphabet[cipheralphabet.index(c)]
        plaintext += p
    return plaintext.lower()
```

* **Morbit Cipher:**
```
hint: A code based on pairs of dots and dashes. Think of a mix of Morse code and numbers... (AZERTYUIO)
cipher: 2557122917522
```

`KangTheConq` clutched again and found out that this is Morbit Cipher:

```py
MORSE_CODE_DICT = {'..-': 'U', '--..--': ', ', '....-': '4', '.....': '5', '-...': 'B', '-..-': 'X', 
                   '.-.': 'R', '--.-': 'Q', '--..': 'Z', '.--': 'W', '-..-.': '/', '..---': '2', 
                   '.-': 'A', '..': 'I', '-.-.': 'C', '..-.': 'F', '---': 'O', '-.--': 'Y', '-': 'T', 
                   '.': 'E', '.-..': 'L', '...': 'S', '-.--.-': ')', '..--..': '?', '.----': '1', 
                   '-----': '0', '-.-': 'K', '-..': 'D', '----.': '9', '-....': '6', '.---': 'J', 
                   '.--.': 'P', '.-.-.-': '.', '-.--.': '(', '--': 'M', '-.': 'N', '....': 'H', 
                   '---..': '8', '...-': 'V', '--...': '7', '--.': 'G', '...--': '3', '-....-': '-'}

MORBIT = ['..', '. ', ' -', '  ', '-.', '--', ' .', '- ', '.-']
KEY = "AZERTYUIO"  # Given key

# Map digits to Morbit symbols using the key
MORBIT_CODE_DICT = dict(zip("123456789", MORBIT))

def morse(ciphertxt): 
    """ Decodes a Morse code string to plaintext. """
    plaintxt = ''
    for word in ciphertxt.strip().split("  "):
        for c in word.strip().split(" "):
            if c in MORSE_CODE_DICT:
                plaintxt += MORSE_CODE_DICT[c]
        plaintxt += ' '
    return plaintxt.strip()

def morbit(ciphertxt):
    """ Decodes a Morbit cipher text into Morse code, then to plaintext. """
    morsetxt = "".join(MORBIT_CODE_DICT[c] for c in ciphertxt if c in MORBIT_CODE_DICT)
    return morse(morsetxt).lower()
```

Combining all of this, we get this final script:

{{<details title="Show script">}}
```py
from pwn import *
import string

HOST = 'decoderunner-6bf56818dcc9ea04.deploy.phreaks.fr'
PORT = 443
p = remote(HOST, PORT, ssl=True)
# p = remote(HOST, PORT)

def latin_gibberish(s):
    data = s[:-2]
    return data[::-1]

def decode_1337(s):
    leet_dict = {
        '4': 'A', '/\\': 'A', '@': 'A', '/-\\': 'A',
        '8': 'B', '|3': 'B', '13': 'B',
        '(': 'C', '<': 'C', '[': 'C', '©': 'C',
        '[)': 'D', '|>': 'D', '|)': 'D',
        '3': 'E', '€': 'E', '[-': 'E',
        '|=': 'F', '/=': 'F',
        '6': 'G', '(_+': 'G',
        '#': 'H', '/-/': 'H', '[-]': 'H', ']-[': 'H', ')-(': 'H', '(-)': 'H', '|-|': 'H',
        '1': 'I', "1'": 'I', '!': 'I', '|': 'I',
        '_|': 'J', '_/': 'J',
        '|<': 'K', '|{': 'K',
        '|_': 'L', '[': 'L', '£': 'L', '1_': 'L',
        '|V|': 'M', '|\/|': 'M', '/\/\\': 'M', '/V\\': 'M',
        '|\|': 'N', '/\/': 'N', '[\]': 'N', '/V': 'N',
        '[]': 'O', '0': 'O', '()': 'O', '<>': 'O',
        '|*': 'P', '|o': 'P', '|°': 'P', '/*': 'P',
        '()_': 'Q', '0_': 'Q', '°|': 'Q', '(_,)': 'Q',
        '|?': 'R', '®': 'R', '|2': 'R',
        '5': 'S', '$': 'S', '§': 'S',
        '7': 'T', '†': 'T', '¯|¯': 'T',
        '(_)': 'U', '|_|': 'U', 'µ': 'U',
        '\/': 'V', '|/': 'V',
        '\/\/': 'W', 'vv': 'W', '\^/': 'W', '\|/': 'W', '\_|_/': 'W',
        '><': 'X', ')(': 'X',
        '`/': 'Y', '¥': 'Y', '\/': 'Y',
        "7_'": 'Z', '>_': 'Z', '≥': 'Z'
    }
    
    result = s
    for leet, char in sorted(leet_dict.items(), key=lambda x: -len(x[0])):
        result = result.replace(leet, char)
    
    return result.lower()

def slumdog(ciphertext):
    cipheralphabet = 'XWYAZBCDQEFGHIKLMNOPJRSTUV'
    plainalphabet = string.ascii_uppercase
    
    plaintext = ''
    for c in ciphertext:
        if c == ' ':
            p = ' '
        else: p = plainalphabet[cipheralphabet.index(c)]
        plaintext += p
    return plaintext.lower()

def weird_morse(s):
    MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}
    MORSE_CODE_DICT_DECODE = {}
    for key, value in MORSE_CODE_DICT.items():
        MORSE_CODE_DICT_DECODE[value] = key
    
    ans = ""
    s = s.split()
    for c in s:
        if "-" in c or "." in c:
            c = c.replace("-", '#').replace(".", '-').replace("#", '.')
            ans += MORSE_CODE_DICT_DECODE[c]
        else:
            ans += c
    return ans

def first_letter(s):
    s = s.split()
    s = [i[0] for i in s]
    s = "".join(s)
    return s.lower()

def decode_chuck_norris(unary_code):
    parts = unary_code.split()
    binary_string = ""
    
    for i in range(0, len(parts), 2):
        bit = '1' if parts[i] == '0' else '0'
        binary_string += bit * len(parts[i + 1])
    
    decoded_text = ""
    for i in range(0, len(binary_string), 7):
        decoded_text += chr(int(binary_string[i:i+7], 2))
    return decoded_text


MORSE_CODE_DICT = {'..-': 'U', '--..--': ', ', '....-': '4', '.....': '5', '-...': 'B', '-..-': 'X', 
                   '.-.': 'R', '--.-': 'Q', '--..': 'Z', '.--': 'W', '-..-.': '/', '..---': '2', 
                   '.-': 'A', '..': 'I', '-.-.': 'C', '..-.': 'F', '---': 'O', '-.--': 'Y', '-': 'T', 
                   '.': 'E', '.-..': 'L', '...': 'S', '-.--.-': ')', '..--..': '?', '.----': '1', 
                   '-----': '0', '-.-': 'K', '-..': 'D', '----.': '9', '-....': '6', '.---': 'J', 
                   '.--.': 'P', '.-.-.-': '.', '-.--.': '(', '--': 'M', '-.': 'N', '....': 'H', 
                   '---..': '8', '...-': 'V', '--...': '7', '--.': 'G', '...--': '3', '-....-': '-'}

MORBIT = ['..', '. ', ' -', '  ', '-.', '--', ' .', '- ', '.-']
KEY = "AZERTYUIO"  # Given key

# Map digits to Morbit symbols using the key
MORBIT_CODE_DICT = dict(zip("123456789", MORBIT))

def morse(ciphertxt): 
    """ Decodes a Morse code string to plaintext. """
    plaintxt = ''
    for word in ciphertxt.strip().split("  "):
        for c in word.strip().split(" "):
            if c in MORSE_CODE_DICT:
                plaintxt += MORSE_CODE_DICT[c]
        plaintxt += ' '
    return plaintxt.strip()

def morbit(ciphertxt):
    """ Decodes a Morbit cipher text into Morse code, then to plaintext. """
    morsetxt = "".join(MORBIT_CODE_DICT[c] for c in ciphertxt if c in MORBIT_CODE_DICT)
    return morse(morsetxt).lower()



baudot_table = {
    "00000": "null", "00100": " ", "10111": "Q", "10011": "W",
    "00001": "E", "01010": "R", "10000": "T", "10101": "Y",
    "00111": "U", "00110": "I", "11000": "O", "10110": "P",
    "00011": "A", "00101": "S", "01001": "D", "01101": "F",
    "11010": "G", "10100": "H", "01011": "J", "01111": "K",
    "10010": "L", "10001": "Z", "11101": "X", "01110": "C",
    "11110": "V", "11001": "B", "01100": "N", "11100": "M",
    "01000": "CR", "00010": "LF", "11011": "Switch to Digits"
}

def baudot_decode(ciphertext):
    bits = ciphertext.split()
    decoded_text = "".join(baudot_table.get(bit, "?") for bit in bits)
    return decoded_text.lower()

def trimethius_decode(ciphertext):
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".lower()
    offset = 3
    
    ans = ""
    
    for i in range(len(ciphertext)):
        idx = ALPHABET.index(ciphertext[i])
        ans += ALPHABET[(idx - offset + len(ALPHABET)) % len(ALPHABET)]
        offset += 1
    
    return ans

def wabi_sabi(ciphertext):
    qod6 = {
        # Row 1
        "A":   "--.--",
        "I":   ".-",
        "U":   "..-",
        "E":   "-.---",
        "O":   ".-...",
        "N": ".-.-.",

        # Row 2
        "KA":  ".-..",
        "KI":  "-.-..",
        "KU":  "...-",
        "KE":  "-.--",
        "KO":  "----",

        # Row 3
        "SA":  "-.-.-",
        "SHI": "--.-.",
        "SU":  "---.-",
        "SE":  ".---.",
        "SO":  "---.",

        # # Row 4
        # "ZA":  "-.-.",
        # "ZI":  "-.--",
        # "ZU":  "..--",
        # "ZE":  ".--.",
        # "ZO":  "---.",

        # Row 5
        "TA":  "-.",
        "CHI": "..-.",
        "TSU": ".--.",
        "TE":  ".-.--",
        "TO":  "..-..",

        # # Row 6
        # "DA":  "-.",
        # "DI":  "----",
        # "DU":  "--.-",
        # "DE":  "-..-",
        # "DO":  "--..",

        # Row 7
        "NA":  ".-.",
        "NI":  "-.-.",
        "NU":  "....",
        "NE":  "--.-",
        "NO":  "..--",

        # Row 8
        "HA":  "-...",
        "HI":  "--..-",
        "FU":  "--..",
        "HE":  ".",
        "HO":  "-..",

        # # Row 9
        # "BA":  ".-..-",
        # "BI":  ".-...",
        # "BU":  "..-..",
        # "BE":  "....",
        # "BO":  ".--..",

        # # Row 10
        # "PA":  ".-..-",
        # "PI":  ".-...",
        # "PU":  "..-..",
        # "PE":  "....",
        # "PO":  ".--..",

        # Row 11
        "MA":  "-..-",
        "MI":  "..-.-",
        "MU":  "-",
        "ME":  "-...-",
        "MO":  "-..-.",

        # Row 12
        "YA":  ".--",
        "YU":  "-..--",
        "YO":  "--",
        
        "RA":  "...",
        "RI":  "--.",
        "RU":  "-.--.",
        "RE":  "---",
        "RO":  ".-.-",
        
        "WA":  "-.-",
        "WI":  ".-..-",
        "WE":  ".--..",
        "WO":  ".---",
    }
    
    DICT = {}
    
    for key, value in qod6.items():
        DICT[value] = key
    
    ciphertext = ciphertext.split()
    ans = ''
    for word in ciphertext:
        if '.' in word or '-' in word:
            ans += DICT[word]
        else:
            ans += word
    
    return ans.lower()

def chord_cipher(ciphertext):
    ciphertext = ciphertext.split()
    dict = {"x02220": 'a', "224442":'b', '032010':'c', 'xx0232':'d', '022100':'e', '133211':'f', '320003':'g', 'x24442':'b', 'x32010':'c'}
    ans = ''
    for i in ciphertext:
        ans += dict.get(i, '?')
    return ans

for i in range(100):
    hint = p.recvuntil(b'cipher: ').decode()
    print(hint)
    cipher = p.recvline().strip().decode()
    print(cipher)
    if ("charabia" in hint):
        msg = latin_gibberish(cipher)
        print(msg)
        p.sendline(msg)
    elif ("1337" in hint):
        msg = decode_1337(cipher)
        print(msg)
        p.sendline(msg)
    elif ("slumdog" in hint):
        msg = slumdog(cipher)
        print(msg)
        p.sendline(msg)
    elif ("It looks like Morse code" in hint):
        msg = wabi_sabi(cipher)
        print(msg)
        p.sendline(msg)
    elif ("hint" not in hint):
        msg = first_letter(cipher)
        print(msg)
        p.sendline(msg)
    elif ("infinity twice" in hint):
        msg = decode_chuck_norris(cipher)
        print(msg)
        p.sendline(msg)
    elif ("CTF 150 years" in hint):
        msg = baudot_decode(cipher)
        print(msg)
        p.sendline(msg)
    elif ("code based on" in hint):
        msg = morbit(cipher)
        print(msg)
        p.sendline(msg)
    elif ("1462" in hint):
        msg = trimethius_decode(cipher)
        print(msg)
        p.sendline(msg)
    elif ("Hendrix" in hint):
        msg = chord_cipher(cipher)
        print(msg)
        p.sendline(msg)
    else:
        break

p.interactive()
```
{{</details>}}