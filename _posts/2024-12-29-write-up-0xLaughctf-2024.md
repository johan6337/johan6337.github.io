---
layout: post
title: Writeups for 0xLaugh CTF 2024
description: Some crypto challenges writeups.
date: '2024-12-29 15:45:00 +0700'
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---

In this CTF i solved 2 chals name 18 Karat Gold and smalleq chals (for saving your time).

## 18 Karat Gold ##

**Problem**:

```python
import random

from Crypto.Util.number import getPrime, bytes_to_long

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537

off_p = random.randint(2**127, 2**128)
off_q = random.randint(2**127, 2**128)
m_p = p - off_p
m_q = q - off_q

a = random.randint(2**10, 2**30)
b = random.randint(2**10, 2**30)

c = -(a * (p**2) + b * q)

flag = b"0xL4ugh{...}"
m = bytes_to_long(flag)
ct = pow(m, e, n)

out = {
    'n': n,
    'e': e,
    'ct': ct,
    'a': a,
    'b': b,
    'c': c,
    'm_p': m_p,
    'm_q': m_q
}

for k,v in out.items():
    print(f"{k} = {v}")

"""
n = 100026398723423136138211894154034770288614747503532436949113002491494106449460190757774983380494662883662759514156256645607757097055204165793773561291660533234897999940438140951945432930055253075454227497805364166473784745078630521842820709173135372171348602971072033705585222846168895750439091425162323558127
e = 65537
ct = 1568671097457723819787489941826403201689202993746529685616897686173734046943320352422354980066671032177408880447270685136791693193733651891710827651302071320562871220718432052045282175335409755157337581925962423926659242477707423166254936675589677604179513253908097118555374028363276063702786366529316802165
a = 940992394
b = 1056172127
c = -83352184464206596895079853804376347820376656184780616999453572407271581212088694294587647030709499949161611518661501735954949703018176640246608971540128107874013647954886640098097662450307282075562519555303842993692138863072691265079602556601831246304763233826916529716537144801413233305868817759015916745384224723253
m_p = 9411642810892552148049212473648795594483585878823360151567704044323967502593629499495235135136297160880420131524539526598684481737338314346462033527462417
m_q = 10627942510488999658618727120778291021034972789433196059586844790118133859622599307622817010095023809491096944097847704202759115514685740339727904782535265
"""
```

**Solution**:

So from the code we can construct two equations then  we use grober basis to solve the system of multiviate equations and recover q and p then we can decrypt the flag.

```python
 
from Crypto.Util.number import *
from sage.all import *
R.<x,y> = QQ[]
PR = PolynomialRing(QQ, 2, 'xy')
x,y = PR.gens()

# Given values
n = 100026398723423136138211894154034770288614747503532436949113002491494106449460190757774983380494662883662759514156256645607757097055204165793773561291660533234897999940438140951945432930055253075454227497805364166473784745078630521842820709173135372171348602971072033705585222846168895750439091425162323558127
e = 65537
ct = 1568671097457723819787489941826403201689202993746529685616897686173734046943320352422354980066671032177408880447270685136791693193733651891710827651302071320562871220718432052045282175335409755157337581925962423926659242477707423166254936675589677604179513253908097118555374028363276063702786366529316802165
a = 940992394
b = 1056172127
c = -83352184464206596895079853804376347820376656184780616999453572407271581212088694294587647030709499949161611518661501735954949703018176640246608971540128107874013647954886640098097662450307282075562519555303842993692138863072691265079602556601831246304763233826916529716537144801413233305868817759015916745384224723253
m_p = 9411642810892552148049212473648795594483585878823360151567704044323967502593629499495235135136297160880420131524539526598684481737338314346462033527462417
m_q = 10627942510488999658618727120778291021034972789433196059586844790118133859622599307622817010095023809491096944097847704202759115514685740339727904782535265

# Create equations
eq1 = -a*(m_p + x)^2 - b*(m_q + y) - c
eq2 = (m_p + x)*(m_q + y) - n

# Create ideal and compute Gröbner basis
I = ideal([eq1, eq2])
B = I.variety(QQ)  # This will find all solutions over QQ

print("Solutions found:", B)

# Solutions found: [{y: 247168677425686384101045327008589914276, x: 192515761548352253972868164482559349330}]

x = 192515761548352253972868164482559349330
y = 247168677425686384101045327008589914276

p = m_p + x
q = m_q + y
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(ct, d, n)
print(long_to_bytes(int(m)))

#b'0xL4ugh{b1v4r14t3_c0pp3r_4nd_g0ld}'
```

## small eq ##

**Problem**:

```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long


p=getPrime(512)
while True:
	w=getPrime(20)
	x=2*w*p-1
	if isPrime(x):
		break

q=getPrime(512*2)
n = p * q *x
e = 65537
m = bytes_to_long(b'redacted')
c = pow(m, e, n)
print(f"{n = }")
print(f"{e = }")
print(f"{c = }")


'''
n = 18186672849609603331344182584568642941078893104802301217241028624469607021717197485036251613075846729705028441094100248337306406098776983108141004863456595015660485098203867670995838502297993710897784135087115777697925848407153788837657722171924264421550564295047937036911411846582733847201015164634546149603743246378710225407507435371659148999942913405493417037116587298256802831009824832360479040621348157491754407277404391337488226402711686156101028879269050800874367763551119682177453648890492731413760738825931684979379268401715029193518612541590846238434595210876468090976194627398214837801868969047036272502669215123
e = 65537
c = 1617999293557620724157535537778741335004656286655134597579706838690566178453141895621909480622070931381931296468696585541046188947144084107698620486576573164517733264644244665803523581927226503313545336021669824656871624111167113668644971950653103830443634752480477923970518891620296211614968804248580381104245404606917784407446279304488720323993268637887493503760075542578433642707326246816504761740168067216112150231996966168374619580811013034502620645288021335483574561758204631096791789272910596432850424873592013042090724982779979496197239647019869960002253384162472401724931485470355288814804233134786749608640103461
'''
```

**Solution**:

So first we have n = p * q * x and x = 2 * w * p - 1 so we can use Cyclotomic Factorization to factorize n and recover p, q.
We first reconstruct the n by multiply n with 2*w then we have: $$n' = 2 * w * n, p' = 2 * w * p - 1 => n' = p' * (p' + 1) * q$$

Now we have p'*(p' + 1) and p' is prime so we can use Cyclotomic Factorization to factorize n' and decrypt the flag.

I give you the link here for cyclotomic factorization: [link](https://johan6337.github.io/posts/RSA-is-fun/#5-factoring-with-cyclotomic-polynomials)

but first we have to brute force w to find the correct w so for time saving i will reveal that w = 733619.

```python

from Crypto.Util.number import *
from sage.all import *
from math import gcd

n = 18186672849609603331344182584568642941078893104802301217241028624469607021717197485036251613075846729705028441094100248337306406098776983108141004863456595015660485098203867670995838502297993710897784135087115777697925848407153788837657722171924264421550564295047937036911411846582733847201015164634546149603743246378710225407507435371659148999942913405493417037116587298256802831009824832360479040621348157491754407277404391337488226402711686156101028879269050800874367763551119682177453648890492731413760738825931684979379268401715029193518612541590846238434595210876468090976194627398214837801868969047036272502669215123

e = 65537
c = 1617999293557620724157535537778741335004656286655134597579706838690566178453141895621909480622070931381931296468696585541046188947144084107698620486576573164517733264644244665803523581927226503313545336021669824656871624111167113668644971950653103830443634752480477923970518891620296211614968804248580381104245404606917784407446279304488720323993268637887493503760075542578433642707326246816504761740168067216112150231996966168374619580811013034502620645288021335483574561758204631096791789272910596432850424873592013042090724982779979496197239647019869960002253384162472401724931485470355288814804233134786749608640103461

w = 733619
n = 2 * w * n

R = PolynomialRing(Zmod(n), "x")

while True:
    poly = R.random_element(2)  # đổi p thành poly
    if gcd(int(poly.leading_coefficient()), n) == 1:
        qr = R.quotient_ring(poly)
        res = gcd(int(list(qr.random_element() ^ n)[1]), n)
        if res > 1 and res < n:
            # Gán p = res, giờ p là prime factor
            p = res
            print("Found prime factor p =", p)
            break

n //= (2 * w)

# 3 possible res from above so i choose res1 cuz it is x 
res3 = 2
res2 = 26739852368567050958274504491661376124317199189459310593174252909472765950279994469346622623055718053199564803837759877205418652474164970952707004614101000504866
res1 = 13369926184283525479137252245830688062158599594729655296587126454736382975139997234673311311527859026599782401918879938602709326237082485476353502307050500252433

res1 = int(res1)
p = (res1 + 1) / (2*w)
p = int(p)
assert isPrime(p)

q = n //(p*res1)

phi = (p-1)*(q-1)*(res1-1)

d = inverse(e, phi)

m = pow(c, d, n)

print(long_to_bytes(int(m)))
#b'0xL4ugh{Fr0m_Th3_r!v3r_t0_Th3_$ea_palestine_will_be_fr33}'
```

That's it for 0xLaugh CTF 2024. Thanks for reading my writeup.