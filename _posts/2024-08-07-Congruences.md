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

We say that a is congruent to b modulo m if $m | (a - b)$, and we write: $a \equiv b \pmod{m}$

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

1. Let $az \equiv b \pmod{n} $ has a solution if and only if $d | b$.
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



