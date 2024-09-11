---
layout: post
title: Abelian groups
description:  Introdution to notion of Abelian groups
date: '2024-08-13 10:16:00 +0700'
categories: [Number Theory]
tags: [Group Theory]
math: true
mermaid: true
---

## I) Definitions, basic properties, and examples ##

### Definition ###

An **Abelian group** is a set G together with a binary operation $\star$ on G such that:

- for all $a,b,c \in G$, $(a \star b) \star c = a \star (b \star c)$ (associativity).
- there exists $e \in G$ (called the identity element) such that for all $a \in G$, $a \star e = e \star a = a$.
- for each $a \in G$, there exists $b \in G$ (called the inverse of a) such that $a \star b = b \star a = e$.
- for all $a,b \in G$, $a \star b = b \star a$ (commutativity).

### Theorem 1 ###

Let G be an abelian group with binary operation $\star$. Then we have:

- G contains only one identity element.
- Every element of G has only one inverse.

### Examples ###

1. The set of integers $\mathbb{Z}$ with the operation of addition is an **abelian group** with 0 being the indentity, and -a being the inverse of a.

2. For each integer n, the set $n\mathbb{Z}$ = {$\{na : a \in \mathbb{Z}\}$ } under addition is an **abelian group**. With 0 being the indetity and -na being the inverse of na.

3. The set of non-negative integers under addition is **not an abelian group** because it does not contain inverses.

4. The set of integers under multiplication is **not an abelian group**, since inverses do not exist for any integer other than $\pm 1$.

5. The set of interger {$\pm 1$} under multiplication forms an **abelian group**, with 1 being the identity and -1 its own inverse.

6. The set of rational numbers $\mathbb{Q}$ under addition is an **abelian group** with 0 being the identity and $\frac{-a}{b}$ being the inverse of $\frac{a}{b}$.

7. The set of non-zero rational number $\mathbb{Q}^{*}$ under multiplication forms an **abelian group** with 1 being the identity and $\frac{b}{a}$ being the inverse of $\frac{a}{b}$.

8. The set $\mathbb{Z}_n$ under addition forms an **abelian group** where $[0]_n$ is the identity and where $[-a]_n$ is the inverse of $[a]_n$.

9. The set $\mathbb{Z}_n^{*}$ under multiplication forms an **abelian group** where $[1]_n$ is the identity and where $[b]_n$ is the inverse of $[a]_n$ if and only if $gcd(a,n) = 1$.

10. The every positive integer n, the set of n-bit strings under bitwise XOR forms an **abelian group** with the n-bit string of all 0s being the identity and each string being its own inverse.

11. The set of alll finite bit strings under concatenation is **not an abelian group** with empty string being the identity and no string having an inverse (except for the empty string).

12. The set of $2 \times 2$ integer matrices with determinant $\pm 1$ under matrix multiplication is **not an abelian group**. Since matrix multiplication is not commutative.



### Theorem 2 ###
Let G be an abelian group. Then for all a,b,c $\in G$, we have:
- if a + b = a + c, then b = c.
- the equation a + x = b has a unique solution for all a,b $\in G$.
- -(a + b) = (-a) + (-b) for all a,b $\in G$.
- -(-a) = a for all a $\in G$.

### Theorem 3 ###
Let G be an abelian group. Then for all a,b $\in G$ and k,l $\in \mathbb{Z}$, we have:
- k(la) = (kl)a = l(ka).
- (k + l)a = ka + la.
- k(a + b) = ka + kb.


### Group's order ###

A group is called trivial if it only contain 1 element that is the indentity. An abelian group G is called finite if it contains a finite number of elements. The number of elements in G is called the order of G and is denoted by $\mid G \mid$.

**Example 1**: The order of the addtitive group $\mathbb{Z}_n$ is n. Iff n = 1, then $\mathbb{Z}_n$ is trivial.

**Example 2**: The order of the multiplicative group $\mathbb{Z}_n^{*}$ is $\phi(n)$, where $\phi(n)$ is the Euler's totient function.

**Example 3**: The additive group of integers $\mathbb{Z}$ is infinite.

## II) Subgroups ##

### Definition ###

Let G be an abelian group, and let H be a non-empty subset of G such that:

- a + b $\in H$ for all a,b $\in H$.
- a $\in H$ implies -a $\in H$.

Then H is called a subgroup of G, denoted by H $\leq$ G.

### Theorem 1 ###


If $H_1$ and $H_2$ are subgroups of G, then so is:
<div style="text-align: center;">
$$
H_1 + H_2 = \{a + b : a \in H_1, b \in H_2\}
$$
</div>

### Theorem 2 ###

If $H_1$ and $H_2$ are subgroups of G, then so is $H_1 \cap H_2$

## III) Cosets and quotient groups ##

### Definition ###
- Let G be an abelian group and H a subgroup of G. For all $a \in G$, the set $a + H$ = {$a + h : h \in H$} is called the **coset** of H in G containing a.

- The set of all cosets of H in G is denoted by G/H. The number of cosets of H in G is denoted by [G:H]. Then G/H = {$a + H : a \in G$}. And G/H called the **quotient group** of G by H.

### Theorem 1 ###

Let G be an abelian group and H a subgroup of G. For all $a,b,c \in G$,we have:
- $a \equiv a \pmod{H}$.
- If $a \equiv b \pmod{H}$, then $b \equiv a \pmod{H}$.
- If $a \equiv b \pmod{H}$ and $b \equiv c \pmod{H}$, then $a \equiv c \pmod{H}$.

### Theorem 2 ###

Every 2 cosets of H in G have the same cardinality.

### Lagrange's theorem ###

If G is a finite abelian group and H is a subgroup of G, then the order of H divides the order of G.

### Theorem 3 ###

Let G be an abelian group and H a subgroup of G. Then the set of cosets of H in G forms a partition of G.

### Theorem 4 ###

Suppose G is a finite abelian group and H is a subgroup of G. Then [G:H] = $\frac{\mid G \mid}{\mid H \mid}$. Where [G:H] is the number of cosets of H in G. 

