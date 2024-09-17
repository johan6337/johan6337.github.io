---
layout: post
title: Quadratic Residue Symbol.
description:  An informal introduction to 3 kinds of quadratics symbol.
date: '2024-09-11 10:16:00 +0700'
categories: [Number Theory]
tags: [quadratic residues]
math: true
mermaid: true
---

## I) Legendre symbol ##

In number theory, the **Legendre symbol** is a completely multiplicative function (that $f(ab) = f(a) \cdot f(b)$).

The **Legendre symbol** is a function of a and prime p defined as:

$$
\left( \frac{a}{p} \right) =
\begin{cases}
0 & \text{if } a \equiv 0 \ (\text{mod } p) \\
1 & \text{if } a \text{ is a quadratic residue mod } p \\
-1 & \text{if } a \text{ is a non-quadratic residue mod } p
\end{cases}
$$

We can determine the properties of a through following formula:

$$\left( \frac{a}{p} \right) \equiv a^{\frac{p-1}{2}} $$


### 1. Properties of the Legendre symbol:

 Given prime p, there are two ways to compute $x^2 \equiv a \mod p$:

- In case **P % 4 = 3** : then $x = a^{\frac{p+1}{4}}$

- In case **p % 4 = 1** : then use [Wiki](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm), [Github](https://github.com/jacksoninfosec/tonelli-shanks/blob/main/tonelli-shanks.py).

- The legendre symbol is periodic in its first(or top) argument, if $a \equiv$ b (mod p), then:
$$\left( \frac{a}{p} \right) = \left( \frac{b}{p} \right)$$

- The Legendre symbol is completely multiplicative function of its top argument:
$$\left( \frac{ab}{p} \right) = \left( \frac{a}{p} \right) \left( \frac{b}{p} \right)$$

- A special case is the Legendre symbol of a square:

$$
\left( \frac{x^2}{p} \right) =
\begin{cases}
0 & \text{if } p \mid x \\
1 & \text{if } p \nmid x \\
\end{cases}
$$

- Using the Legendre symbol, the quadratic reciprocity law can be stated concisely:

$$\left( \frac{p}{q} \right) \left( \frac{q}{p} \right) = (-1)^{\frac{p-1}{2} \frac{q-1}{2}}$$

## II) Jacobi symbol ##

The **Jacobi symbol** is a generalization of the Legendre symbol, which is defined for all integer a and **odd integer** n. It is mainly used in computational number theory, especially in primality testing and factorization algorithms.

For any integer a and composite integer n , the Jacobi symbol is defined as:

$$ \left( \frac{a}{n} \right) = \prod_{i=1}^{k} \left( \frac{a}{p_i} \right)^{e_i} $$

where $n = p_1^{e_1} \cdot p_2^{e_2} \cdot \ldots \cdot p_k^{e_k}$ is the prime factorization of n.

### 1. Properties of the Jacobi symbol ###

**Note: Jacobi symbol is defined only when the upper argument(numerator) is an integer and the lower argument(denominator) is an odd number**

1. If n is an odd prime, then the Jacobi symbol is the same as the Legendre symbol.

2. If $$a \equiv b \mod n$$, then $$\left( \frac{a}{n} \right) = \left( \frac{b}{n} \right) = \left( \frac{a \pm mb}{n} \right)$$

3. $$\left( \frac{a}{n} \right) =
\begin{cases}
0 & \text{if } gcd(a,n) \neq 1 \\
\pm 1 & \text{if } gcd(a,n) = 1
\end{cases}
$$

If either the top or bottom argument is fixed, the Jacobi symbol is a multiplicative function of the other argument:

4. $$\left( \frac{ab}{n} \right) = \left( \frac{a}{n} \right) \left( \frac{b}{n} \right)$$, so $$\left( \frac{a^2}{n} \right) = {\left( {\frac{a}{n}} \right)}^2 = 1 or 0$$

5. $$ \left({\frac {a}{mn}}\right)=\left({\frac {a}{m}}\right)\left({\frac {a}{n}}\right),\quad {\text{so }}\left({\frac {a}{n^{2}}}\right)=\left({\frac {a}{n}}\right)^{2}=1{\text{ or }}0.$$

The **law of quadratic reciprocity**: if m and n are odd positive coprime integers, then:

6. $$ \left( \frac{m}{n} \right) \left( \frac{n}{m} \right) = (-1)^{\left( \frac{m-1}{2} \right) \cdot \left( \frac{n-1}{2} \right)} =
\begin{cases}
1 & \text{if } n \equiv 1 \pmod{4} \text{ or } m \equiv 1 \pmod{4}, \\
-1 & \text{if } n \equiv m \equiv 3 \pmod{4}
\end{cases}
$$

Like the Legendre symbol: $\frac{a}{n}$= −1 then a is a quadratic nonresidue modulo n.
If a is a quadratic residue modulo n and gcd(a,n) = 1, then $\frac{a}{n}$= 1. But, unlike the Legendre symbol:

If $\frac{a}{n}$ then a may or may not be a quadratic residue modulo n.
This is because for a to be a quadratic residue modulo n, it has to be a quadratic residue modulo every prime factor of n. However, the Jacobi symbol equals one if, for example, a is a non-residue modulo exactly two of the prime factors of n.

### 2. Python implementation of calculating Jacobi symbol ###

```python
def jacobi(a,n):
    assert n > 0
    assert n % 2 == 1
    a = a % n
    t = 1
    while a != 0:
        while a % 2 == 0:
            a /= 2
            r = n%8
            if r == 3 or r == 5:
                t = -t
        r = n
        n = a
        a = r
        if a % 4 == 3 and n % 4 == 3:
            t = -t
        a = a % n
    if n == 1:
        return t
    else:
        return 0
   
```

## III) Kronecker symbol ##

In number theory, Krocecker symbol is a generization of Jacobi symbol to all integer n. 
Let n be a non-zero integer, with prime factorization:

$$ n=u\cdot p_{1}^{e_{1}}\cdots p_{k}^{e_{k}},$$

where u is a unit (i.e, $u = \pm 1$),and the $p_i$ are primes. Let a be an integer. The Kronecker symbol is defined as:

$$ \left({\frac {a}{n}}\right):=\left({\frac {a}{u}}\right)\prod _{i=1}^{k}\left({\frac {a}{p_{i}}}\right)^{e_{i}}.$$

For odd $p_i$, the number $\left( \frac{a}{p_i} \right)$ is simply the usual Legendre symbol.

Since it extends the Jacobi symbol, the quantity $\left( \frac{a}{u} \right)$ is simply 1 when u = 1. When u = -1, we have:


$$ \left({\frac {a}{-1}}\right):={\begin{cases}-1&{\mbox{if }}a<0,\\1&{\mbox{if }}a\geq 0.\end{cases}}$$

### 1. Properties of the Kronecker symbol ###

The Kronecker symbol shares many basic properties of the Jacobi symbol, under certain restrictions:

- $$ \left({\tfrac {a}{n}}\right)=\pm 1$$ if gcd(a,n) = 1, otherwise $\frac{a}{n} = 0$.

- $$ \left({\tfrac {ab}{n}}\right)=\left({\tfrac {a}{n}}\right)\left({\tfrac {b}{n}}\right)$$ unless $$ n=-1 $$, one of $$ a,b $$ is zero and the other one is negative.
 
- $$ \left({\tfrac {a}{mn}}\right)=\left({\tfrac {a}{m}}\right)\left({\tfrac {a}{n}}\right)$$ unless $$ a=-1$$, one of $$m,n$$ is zero and the other one has odd part (definition below) congruent to $$ 3{\bmod {4}}$$.

- For \(n > 0\), we have
  $$
  \left( \frac{a}{n} \right) = \left( \frac{b}{n} \right)
  $$
  whenever
  $$
  a \equiv b \pmod{
  \begin{cases} 
  4n & \text{if } n \equiv 2 \pmod{4}, \\
  n & \text{otherwise}.
  \end{cases}}
  $$
  
  If additionally \(a\) and \(b\) have the same sign, the same also holds for \(n < 0\).

- For ($$a \not\equiv 3 \pmod{4}$$) and ($$a \neq 0$$), we have
$$
\left( \frac{a}{m} \right) = \left( \frac{a}{n} \right)
$$
whenever
$$
m \equiv n \pmod{
\begin{cases} 
4|a| & \text{if } a \equiv 2 \pmod{4}, \\
|a| & \text{otherwise}.
\end{cases}}
$$

On the other hand, the Kronecker symbol does not have the same connection to quadratic residues as the Jacobi symbol. In particular, the Kronecker symbol $$ \left({\tfrac {a}{n}}\right)$$ for $$ n\equiv 2{\pmod {4}}$$ can take values independently on whether $$ a$$ is a quadratic residue or nonresidue modulo $$ n$$.

**Quadratic reciprocity**

For any nonzero integer n, let n' denote its **odd part**: $$n = 2^e n'$$ where $$n'$$ is odd for $$n = 0$$, we put 0' = 1. Then the following **symmetric version** of quadratic reciprocity holds for every pair of integers m, n such that gcd(m, n) = 1:

$$
\left( \frac{m}{n} \right) \left( \frac{n}{m} \right) = \pm (-1)^{\frac{m'-1}{2} \cdot \frac{n'-1}{2}},
$$

where the $\pm$ sign is equal to + if $$m \geq 0$$ or $$n \geq 0$$ and is equal to - if m < 0 and n < 0.





 