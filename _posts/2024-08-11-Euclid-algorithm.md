---
layout: post
title: Euclid's algorithm
description: Euclid's algorithm for computing the greatest common divisor and further applications.
date: '2024-08-11 11:18:00 +0700'
categories: [Number Theory]
tags: [Euclid's algorithm, Greatest common divisor]
math: true
mermaid: true
---

## I) The basic Euclidean algorithm ##

Let a,b be integers, with $$a \geq b > 0$$. Using the division with remainder property, define the integers $$r_0, r_1,...,r_{n+1}$$ and $$q_1,...,q_n$$ where $$n \geq 0$$ as follows:

$$
\begin{align*}
a &= r_0, \\
b &= r_1 , \\
r_{0} &= r_{1}q_{1} + r_{2} \quad \quad\quad (0 < r_2 < r1 ) \\
    ... \\
r_{i-1} &= r_{i}q_{i} + r_{i+1} \quad\quad(0 < r_{i+1} < r_i ) \\
    ... \\
r_{n-2} &= r_{n-1}q_{n-1} + r_{n} \quad  (0 < r_{n} < r_{n-1} ) \\
r_{n-1} &= r_{n}q_{n}   \quad \quad \quad \quad \quad  (r_{n+1} = 0 ) \\
\end{align*}
$$

**Example**:
Let a = 100 and b = 35. Then the above theorem illustates the following:

| i | 0 | 1 | 2 | 3   |  4  |
|---|------------|----------|----------|
| $r_i$ | 100  | 35    | 30    |  5    |  0    |
| $q_i$ |      | 2     | 1     | 6     |     |

So we have gcd(a,b) = $r_3$ = 5.4

**Euclidean algorithm**: On input a,b where a and b are integers with $$a \geq b \geq 0$$, the Euclidean algorithm is the following:
 
```python
def Euclid_algorithm(c,d):
    a = c
    b = d
    while b != 0:
        e = a % b
        a,b = b,e
    return a
```

## II) The extended Euclidean algorithm ##

Let $$a,b,r_0,...,r_{n+1}$$ and $$q_1,...,q_n$$ be as in the basic Euclidean algorithm. Then the extended Euclidean algorithm computes integers $$s_0,...,s_{n+1}$$ and $$t_0,...,t_{n+1}$$ such that:

$$
\begin{align*}
s_0 &= 1, \quad \quad \quad \quad \quad t_0 = 0 \\
s_1 &= 0, \quad \quad \quad \quad \quad t_1 = 1 \\
s_{i+1} &= s_{i-1} - q_{i}s_{i}, \quad t_{i+1} = t_{i-1} - q_{i}t_{i} \quad \quad (i = 1,...,n)
\end{align*}
$$

Then:

- for $$i = 0,...,n + 1$$, we have $$a{s_i} + b{t_i} = r_i$$; in particular, $$a{s_n} + b{t_n} = gcd(a,b)$$.

**Example**: Let a = 100 and b = 35. Then the above theorem illustates the following:

| i | 0 | 1 | 2 | 3   |  4  |
|---|------------|----------|----------|
| $r_i$ | 100  | 35    | 30    |  5    |  0    |
| $q_i$ |   | 2    | 1   |  6    |    |
| $s_i$ | 1  | 0    | 1   |  -1    |  7  |
| $t_i$ | 0  | 1    | -2   |  3    |  -20  |


**Extended Euclidean algorithm**: On input a,b ,compute integers d,s,t such that d = gcd(a,b) and d = as + bt, as follows:

```python
from math import floor

def Extended_Euclidean_algorithm(a,b):
    r,r_1,s,s_1,t,t_1 = a,b,1,0,0,1
    while r_1 != 0:
        q = floor(r/r_1) 
        r_2 = r % r_1
        r,s,t,r_1,s_1,t_1 = r_1,s_1,t_1,r_2,(s-s_1*q),(t-t_1*q)
    d = r
    return d,s,t
```


