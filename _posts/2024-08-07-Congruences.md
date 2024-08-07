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

We say that a is congruent to b modulo m if m | (a-b), and we write: $a \equiv b \pmod{m}$

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

1. Let $az \equiv b \pmod{n} $ has a solution if and only if d | b.
2. Let $az \equiv 0 \pmod{n} $ if and only if $z \equiv 0 \pmod{n/d}$.
3. For all $z,z' \in \mathbb{Z}$, we have $az \equiv az' \pmod{n}$ if and only if $z \equiv z' \pmod{n/d}$.

Further consequences of the theorem:

**A cancellation law** : If  $az \equiv az' \pmod{n}$  and d is relatively prime to n, then  $z \equiv z' \pmod{n}$.

**Modular inverses** : If $az \equiv 1 \pmod{n}$, then z is called the modular inverse of a modulo n, and is denoted by $a^{-1}$.

## Chinese Remainder Theorem ##






