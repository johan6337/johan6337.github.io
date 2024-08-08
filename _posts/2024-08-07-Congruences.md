---
layout: post
title: Congruences
description: All related to congruences
date: '2024-08-07 14:46:00 +0700'
categories: [Number Theory]
tags: [congruences]
math: true
mermaid: true
---


## I) Definition and basic properties ##

We say that a is congruent to b modulo m if $m \mid (a - b)$, and we write: $a \equiv b \pmod{m}$

Example: $7 \equiv 2 \pmod{5}$, $7 \equiv 12 \pmod{5}$, $7 \equiv -3 \pmod{5}$.

### Theorem 1 ###

1. $a \equiv a \pmod{m}$.
2. If $a \equiv b \pmod{m}$ then it implies that $b \equiv a \pmod{m}$.
3. If $a \equiv b \pmod{m}$ and $b \equiv c \pmod{m}$, then $a \equiv c \pmod{m}$.

### Theorem 2 ###

Let a,a',b,b' be integers and m be a positive integer. If $a \equiv a' \pmod{m}$ and $b \equiv b' \pmod{m}$, then:

1. $a+b \equiv a'+b' \pmod{m}$.
2. $ab \equiv a'b' \pmod{m}$.

## II) Solving linear congruences ##

### Theorem 1 ###

1. Let $az \equiv b \pmod{n} $ has a solution if and only if $d \mid b$.
2. Let $az \equiv 0 \pmod{n} $ if and only if $z \equiv 0 \pmod{n/d}$.
3. For all $z,z' \in \mathbb{Z}$, we have $az \equiv az' \pmod{n}$ if and only if $z \equiv z' \pmod{n/d}$.

Further consequences of the theorem:

**A cancellation law** : If  $az \equiv az' \pmod{n}$  and d is relatively prime to n, then  $z \equiv z' \pmod{n}$.

**Modular inverses** : If $az \equiv 1 \pmod{n}$, then z is called the modular inverse of a modulo n, and is denoted by $a^{-1}$.

## III) Chinese Remainder Theorem ##

Let : <br>
$X \equiv a_1 \pmod{m_1}$ <br>
$X \equiv a_2 \pmod{m_2}$ <br>
          ... <br>
$X \equiv a_n \pmod{m_n}$ <br>

Then exist a unique solution: <br>

$M \equiv (a_1.M_1.M_1^{-1} + a_2.M_2.M_2^{-1} + ... + a_n.M_n.M_n^{-1}) \pmod{M}$ <br>

**Where** :
- $M = m_1.m_2...m_n$ and $M_i = M/m_i$ 
- $M_1.M_1^{-1} \equiv 1 \pmod{m_1}$  

**Example : Solve the following system of congruences:**
$X \equiv 2 \pmod{3}$ <br>
$X \equiv 3 \pmod{5}$ <br>
$X \equiv 2 \pmod{7}$ <br>

 
 
|    a     |     m    |    M     |  $M^{-1}$ |          |
|----------|----------|----------|----------|----------|
| $a_1 = 2$| $m_1 = 3$| $M_1 = 35$| $M_1^{-1} = 2$|          |
| $a_2 = 3$| $m_2 = 5$| $M_2 = 21$| $M_2^{-1} = 1$|  $M = 105$ |
| $a_3 = 2$| $m_3 = 7$| $M_3 = 15$| $M_3^{-1} = 1$|          |

$X \equiv (2.35.2 + 3.21.1 + 2.15.1) \equiv 23 \pmod{105}$ <br>

## IV) Residue classes ##

### 1) Definition ###

To define residue classes, we write: <br>
$$ [a] = \{x \in \mathbb{Z} | x \equiv a \pmod{m} \} $$

**Example:** <br>

The residue class of $a \equiv 3 \pmod{5}$ is: $$[3] = \{...,-7,-2,3,8,13,...\}$$

We also have some binary operations: <br>
- $[a] + [b] = [a + b]$
- $[a].[b] = [a . b]$

### 2) Theorem 1 ###
Let n be a positive integer. Then $Z_n$ consists of n residue classes: $[0],[1],...,[n-1]$.

Addtion and multiplication in $Z_n$ have a very natural algebraic structure. For a,b,c $\in Z_n$, we have: <br>
- a + b = b + a
- (a + b) + c = a + (b + c)
- ab = ba
- (ab)c = a(bc)
- a(b + c) = ab + ac

The residue class $[0]$ is the **additive identity**; that is, for all $a \in Z_n$, we have $a + [0] = a$. The residue class $[0]$ also has the property that $a.[0] = [0]$ for all $a \in Z_n$. <br>

Every $a \in Z_n$ has an **additive inverse** $-a \in Z_n$ such that $a + (-a) = [0]$. <br>

The residue class $[1]$ acts as a **multiplicative identity**; that is, for all $a \in Z_n$, we have $a.[1] = a$. <br>

For $a \in Z_n$, we call $b \in Z_n$ a **multiplicative inverse** of a if $ab = [1]$. Not all $a \in Z_n$ have a multiplicative inverse. We define $Z_n^{*}$ to be the set of all $Z_n$ that have a multiplicative inverse.
We have: 
$$Z_n^{*} = \{a \in Z_n | gcd(a,n) = 1\}$$

If n is prime , then gcd(a,n) = 1 for a = 1,...,n - 1, and we have $Z_n^{*} = Z_n - {[0]}$.

## V) Euler's phi function ##

### 1) Definition ###

**Euler's phi function** (also called **Euler's totient function**) is defined for all positive integers n as: <br>
$$\phi(n) = \mid Z_n^{*}\mid$$

Equivalently, $\phi(n)$ is the number of positive integers less than n that are relatively prime to n. <br>

**Example:** $\phi(8) = 4$ because the positive integers less than 8 that are relatively prime to 8 are 1,3,5,7. <br>

### 2) Theorem 1 ###
Let $(n_i)_{i = 1}^{k}$ be a family of positive integers that are pairwise relatively prime, and let $n = \prod_{i = 1}^{k} n_i$. Then:

$$\phi(n) = \prod_{i=1}^{k} \phi(n_i).$$

### 3) Theorem 2 ###
Let p be a prime number and k be a positive integer. Then: <br>
$$\phi(p^k) = p^k - p^{k-1} = p^{k-1}(p-1).$$

### 3) Theorem 3 ###

If $n = p_1^{e1}...p_r^{er}$ is the factorization of n into prime powers, then: <br>
$$\phi(n) = \prod_{i = 1}^{r}p_i^{e_i-1}(p_i-1) = n \prod_{i=1}^{r}(1-1/p_i)$$

## VI) Euler's theorem and Fermat's little theorem ##

If $a = [a]$ with $a \in Z_n^{*}$ (and gcd(a,n) = 1, since $a \in Z_n^*$), then k is also called the multiplicative order of a modulo n, such that:
$$a^{k} \equiv 1 \pmod{n}$$

From the above discussion, we see that the first k powers of a, that is, $a^1,a^2,...,a^k$, are distinct modulo n. The next k powers of a, that is, $a^{k+1},a^{k+2},...$, are congruent to $a,a^2,...$ modulo n. <br>

### 1) Theorem 1 ###
Let n be a positive integer, and let a be an element of $Z_n^*$ of multiplicative order k. Then for every $i \in Z$, we have $a^i = 1$ if and only if $k \mid i$. <br>

**Example:** Let n = 7 and a = 3. Then $Z_7^* = \{1,2,3,4,5,6\}$, and we have: <br>

<div style="text-align: center;">

|  i  |   1  |   2   |   3   |   4   |   5   |   6   |
|-----|------|-------|-------|-------|-------|-------|
|$1^i \pmod{7}$| 1 | 1 | 1 | 1 | 1 | 1 |
|$2^i \pmod{7}$| 2 | 4 | 1 | 2 | 4 | 1 |
|$3^i \pmod{7}$| 3 | 2 | 6 | 4 | 5 | 1 |
|$4^i \pmod{7}$| 4 | 2 | 1 | 4 | 2 | 1 |
|$5^i \pmod{7}$| 5 | 4 | 6 | 2 | 3 | 1 |
|$6^i \pmod{7}$| 6 | 1 | 6 | 1 | 6 | 1 |

</div>
So with modulo 7 we have: 1 has order 1; 6 has order 2; 3 has order 6; 2,4,5 have order 3. <br>

### 2) Euler's theorem ###
Let n be a positive integer and $a \in Z_n^*$. Then: $a^{\phi(n)} = 1$.In particular, the multiplicative order of a devides $\phi(n)$.

### 3) Fermat's little theorem ###

For every prime p,and every $a \in Z_p^*$, we have: $a^{p} = a$. <br>







 














