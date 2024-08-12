---
layout: post
title: Computing with large integers
description: "Some standard asymptotic notations,introduce the formal computational model, and discuss the complexity of some basic algorithms."
date: '2024-08-09 17:58:00 +0700'
categories: [Number Theory]
tags: [Big-O]
math: true
mermaid: true
---

## I) Asymptotic Notations ##

Let f and g be real-valued functions. Then:

- $$f = O(g)$$ means that $$ f(x)\ \leq cg(x)$$ for some positive constant c and sufficiently large x("f is big-0 of g").
- $$f = \omega(g)$$ means that $$ f(x) \geq cg(x)$$ for some positive constant c and sufficiently large x("f is omega of g").
- $$f = \Theta(g)$$ means that $$cg(x) \leq f(x) \leq dg(x)$$ for some positive constants c and d and sufficiently large x("f is big-Theta of g").
- $$f = o(g)$$ means that $$\frac{f(x)}{g(x)} \rightarrow 0 \text{ as } x \rightarrow \infty$$ ("f is little-o of g").
- $f \sim g$ means that $$\frac{f(x)}{g(x)} \rightarrow 1$$ as $$x \rightarrow \infty$$ ("f is equivalent to g").

**Example 1**: Let $$f(x) = x^2$$ and $$g(x) = 2x^2 - 10x + 1$$. Then $f = O(g)$ abd f = $$\Omega(g)$$. Indeed, f = $$\theta(g)$$.

**Example 2**: Let $$f(x) = x^2$$ and $$g(x) = x^2 - 10x + 1$$. Then $$f \sim g$$.

**Example 3**: Let $$f(x) = x^2$$ and $$g(x) = x^3$$. Then $$f = o(g)$$.

## II) Note ##

For an integer a, we define its bit-length below:
$$\text{len}(a) = \begin{cases} 
1 & \text{if } a = 0 \\ 
\lfloor \log_2 |a| \rfloor + 1 & \text{if } a \neq 0 
\end{cases}$$

### Theorem 1 ###
Let a and b be arbitrary integers.
- We can compute $a \pm b$ in $$O(\text{len}(a) + \text{len}(b))$$.
- We can compute $a.b$ in $$O(\text{len}(a).\text{len}(b))$$.
- If $b \neq 0$, we can compute the quotient q = $$\lfloor a/b \rfloor$$ and the remainder r = $$a \mod b$$ in $$O(\text{len}(a).\text{len}(b))$$.

## References

1.Victor Shoup, *A Computational Introduction to Number Theory and Algebra*, version 2.