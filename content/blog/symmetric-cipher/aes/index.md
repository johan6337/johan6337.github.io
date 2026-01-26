---
layout: post
title: RSA is fun (Part 1).
description:  An informal introduction about all kinds of RSA attacks.
date: '2024-09-11 10:16:00 +0700'
categories: [RSA]
tags: [RSA]
math: true
mermaid: true
---

## I) Brief introduction about RSA ##

### Definition ###

RSA (Rivest-Shamir-Adleman) is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest and best-known asymmetric encryption schemes. The security of RSA relies on the practical difficulty of factoring the product of two large prime numbers, the factoring problem. In this blog post, we will discuss some attack that i collected from various sources.

### RSA encryption and decryption ###

RSA involves a public key and a private key. The public key can be known by everyone and is used for encrypting messages. Messages encrypted using the public key can only be decrypted with the private key. The keys for the RSA algorithm are generated the following way:

1. Choose two distinct prime numbers $p$ and $q$.
2. Compute $n = pq$.
3. Compute $\phi(n) = (p-1)(q-1)$.
4. Choose an integer $e$ such that $1 < e < \phi(n)$ and $gcd(e, \phi(n)) = 1$.
5. Compute $d$ such that $ed \equiv 1 \pmod{\phi(n)}$.

Therefore, one can encrypt a message $m$ by computing $c \equiv m^e \pmod{n}$ and decrypt it by computing $m \equiv c^d \pmod{n}$. And now we move on to the main topic of this blog post.

## II) Attacks on RSA ##

So in this section, we will discuss some technique in order to factorize the RSA modulus which break the RSA trapdoor function. Below are some technique i gather on the internet and in some CTF competition that i participated in. So if there are any mistake or any technique you know that not involve in this blog post, please let me know by contact me via twitter or email.

### 1. Fermat factorization ###

**Fermat Factorization** method bases on the fact that any integers can be express as the difference of two squares. If $n$ is a number that can be expressed as **$n = a^2 - b^2$**, then **$n = (a+b)(a-b)$**. 

Fermat's factorization method factors N into p and q very efficiently if p and q share half of their leading bits. In other words, if the gap between p and q is below the $\sqrt{N}$. Especially, when the difference is below $2n^{1/4}$, the method run in trivial time.

**Python implementation**:

```python
from math import isqrt, ceil
 
def fermat_factorization(n):
    a = ceil(pow(n, 0.5))
    while True:
        b2 = a*a - n
        b = pow(b2,0.5)
        if b*b == b2:
            break
        a += 1
    return (a+b), (a-b)

n = 115792089237316195448679392282006640413199890130332179010243714077028592474181
p, q = fermat_factorization(n)
assert n == p*q
```

**Resources**: [Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)

### 2. Pollard's p-1 algorithm ###

Pollard's p-1 factorization method is a special-purpose method, which is only suitable for numbers with small factors. In other word, the algorithm is effient when 1 factor of n is B-smooth prime( that p - 1 is the product of several small prime).

**Example** : p = 61 is a 5-smooth prime because $p-1 = 2^2 * 3 * 5$.

**Python implementation**:

```python
from gmpy2 import gcd,fac

#step 1: choose a random number a
a = 2
n = 1403 #the factor of n (61) is smooth
#step 2: choose the bound B. In this case B = 10 is safe.
# the bound for the factor of p (generally, B is 65535), larger B run slower but more accurate, smaller B run faster but less accurate. Value of B depend on the powersmooth of p.
B = 10 

while True:
    M = fac(B) #step 3 : calculate M = B!
    d = gcd(pow(a,M,n)-1,n) #step 4: calculate d = gcd(a^M - 1, n). For understanding, read the resoure i provided below.
    if d == 1:  #if d == 1, then the smoothpower of p is higher than B so increase B
        B += 1
    elif d == n: #if d == n, then the smoothpower of p is lower than B so decrease B
        B -= 1
    else:  #if d is a factor of n, then we found the factor of n
        assert d*(n//d) == n
        print(d, n//d)
        break

```

**Resources**: [Wikipedia](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm)

### 3. Williams' p+1 algorithm ###

William's p+1 algorithm is a generalization of Pollard's p-1 algorithm. The algorithm is suitable for numbers with small factors. The algorithm is efficient when 1 factor of n is B-smooth prime( that p + 1 is the product of several small prime).

**Example** : p = 61 is a 5-smooth prime because $p+1 = 2^2 * 3 * 5$.

**Python implementation**:

```python
from gmpy2 import fac
import itertools
from math import gcd

# function to find the Mth number in Lucas sequence generate by A. For more information, read the resource i provided below.
def Mth_lucas(M,A,N):
    x = A
    y = (A**2-2) % N
    for i in bin(M)[3:]:
        if i == '1':
            x = (x*y - A) % N
            y = (y**2 - 2) % N
        else:
            y = (x*y - A) % N
            x = (x**2 - 2) % N
    return x

# function to find the factor of n
def william_factor(N,A):
    for i in itertools.count(1): #loop through all the factorials
        x = Mth_lucas(fac(i),A,N) #calculate the fac(i) number in the lucas sequence
        d = gcd(x-2,N) #calculate the gcd of x-2 and N
        if d == 1 or d == N: 
            continue
        else: # if 1 < d < N then d is non-trivial factor of N
            return d # 
n = 451889 
A = 6  
p = william_factor(n,A)
q = n//p
assert n == p*q
```

Resources: [Wikipedia](https://en.wikipedia.org/wiki/Williams%27_p_%2B_1_algorithm)

### 4. Lenstra elliptic-curve factorization ###

ECM factor is a factorization algorithm that uses elliptic curves. The algorithm is efficient when the factor of n is small(that around 50-60 digits) so it is considered to be special-purpose factorization method. The algorithm is based on the fact that the number of points on an elliptic curve over a finite field is a multiple of the field size. 

**Python implementation**:

```python

 
from sage.all import *
import re

def ecm(n, d_max):
    while True:
        assert gcd(n, 6) == 1   #some assertions imply that ecm not optimal for this case
        assert Integer(n).is_perfect_power() == False
        while True:
            b, x1, y1 = [randint(1, n) for _ in range(3)]   #randomly choose b, x1, y1
            c = (y1**2 - x1**3 - b * x1) % n  #calculate c
            if gcd(4 * b**3 + 27 * c**2, n) == 1: #check if the curve is nonsingular
                break
        E = EllipticCurve(Zmod(n), [b, c]) 
        P = E(x1, y1)
        Q = P
        for i in range(2, d_max): #loop through 2 to d_max
            try:
                Q = i*P #calculate i*P
                A = P
                P = Q
            #in ecc scalar multiplication, we need to compute the slope between 2 point and it involve the division of 2 numbers modulo n so we need to compute modulo inverse 
            # that return ZeroDivisionError if gcd(n, x) != 1. That help us retrive the factor of n .
            except ZeroDivisionError as e: 
                fault = list(map(ZZ, re.findall('[0-9]+', e.args[0]))) # extract the value of x
                f = gcd(fault[0], n)
                if f > 1 and f < n:
                    return [f, n//f]

#Test
from Crypto.Util.number import *

p = getPrime(32)
q = getPrime(32)
n = p * q
d_max = 32  #choose the bound d_max equal to the number of bits of the prime factors. larger d_max will increase the probability of success but slower running time.
print(ecm(n, d_max))
```

Resources: ["Rational Points on Elliptic Curves" by Joseph H. Silverman and John Tate, page 139](https://github.com/isislovecruft/library--/blob/master/cryptography%20%26%20mathematics/elliptic%20curve%20cryptography/Rational%20Points%20on%20Elliptic%20Curves%20(2015)%20-%20Silverman%2C%20Tate.pdf)

### 5. Factoring with Cyclotomic Polynomials ###

This is a less well-known factor technique than mentioned above. I come accrross this technique when i reading hakid29's blog. Checkout [his blog](https://velog.io/@hakid29/Quotient-Ring-and-isomorphism#1-compfest-ctf-2023-swusjask-encryption) here (2nd chal and 3rd chal). In this technique, several keyword we need to know are:

+ **Cyclotomic Polynomial**: We not dive deep into this topic but you can checkout [here](https://en.wikipedia.org/wiki/Cyclotomic_polynomial) for some example of nth cyclotomic polynomial (we will use some of these in the attack).

+ **Quotient Ring**: chapter 16,17,18 in this link "abstract.ups.edu/aata/aata.html"

+ **Field, order, and isopmorphism**: chapter 21,22,23 in this "abstract.ups.edu/aata/aata.html"

After we understand the above keywords, let analyse the 2nd chal for example. First let look at the challenge: 

```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long


def sus(sz, d):
    while True:
        p = getPrime(sz)
        pp = sum([p**i for i in range(d)])
        if isPrime(pp):
            return p, pp


p, q = sus(512, 3)
r = getPrime(512 * 3)
n = p * q * r
e = 65537
m = bytes_to_long(open("flag.txt", "rb").read().strip())
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
```

It easy to see that **$$n = p*(p*2 + p + 1)*r$$** which is n is a multiple of 3rd cyclotomic polynomial ($$x^2 + x + 1$$). So we can factorize n by using 3th clycloctomic polynomial. First we define a quotient ring **$$R = Z_n[x]/f(x)$$** where f(x) is a random of 3rd degree polynomial. That every element in this quotient ring can be express that **$$a_0 + a_1x + a_2x^2$$**. So if f(x) is irreducible in **$$F_p^3$$** then we have the isomorphism between **$$F_p^3$$** and **$$F_p^3[x]/f(x)$$**. So every polynomials in **$$F_p^3[x]/f(x)$$** have order **$$p^3 - 1$$** which we can factorize to **$$(p - 1)(p^2 + p + 1)$$**.

So the magical things here is when we pick a random element a in the quotient ring and power it to n, we have **$$a^{n} = a^{k*(p^2 + p + 1)}$$** that a have order **$$p - 1$$** in **$$F_p^3[x]/f(x)$$** which imply that a is in the subfield **$$GF(p)$$** of **$$GF(p^3)$$**. Then a will have the form **$$a + 0x + 0x^2$$** in **$$F_p^3[x]/f(x)$$** so in **$$Z_n[x]/f(x)$$**, a will have the form **$$a + p*x + p*x^2$$**. So we can compute the gcd of n with the x or **$$x^2$$** coefficient of a to get the factor of n.