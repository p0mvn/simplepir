# Lattice-based Cryptography Primer

Lattice-based crytography is a type of cryptography that uses lattices as the underlying mathematical structure.

Latest post-quantum encryption schemes are based on lattice-based cryptography. In turn, PIR protocols are based on these encryption schemes. 

## Short Integer Solutions (SIS) Problem

The **Short Integer Solutions (SIS)** problem is a fundamental computational problem in lattice-based cryptography, closely related to the Learning With Errors (LWE) problem.

### Problem Definition

Given:
- A random matrix **A** ∈ ℤ_q^{n × m} (n rows, m columns, entries mod q)
- A bound β > 0

**Goal**: Find a non-zero vector **z** ∈ ℤ^m such that:

1. **A · z = 0 (mod q)** — z is in the kernel of A
2. **‖z‖ ≤ β** — z is "short" (has small norm)

### Why is it Hard?

Finding *any* solution to **Az = 0** is easy (just linear algebra). The hard part is finding a **short** solution.

The difficulty comes from the connection to lattice problems:
- The set of all solutions forms a **lattice** (a discrete additive subgroup of ℝ^m)
- Finding short vectors in a lattice is believed to be computationally hard
- SIS is as hard as worst-case lattice problems like **SIVP** (Shortest Independent Vectors Problem) and **GapSVP** (Gap Shortest Vector Problem)

### Parameters

The hardness depends on the relationship between:
- **n**: security parameter (dimension)
- **m**: number of columns (typically m > n log q)
- **q**: modulus
- **β**: bound on solution norm

If β is too large, solutions are easy to find. If too small, solutions may not exist.

### Comparison with LWE

| SIS | LWE |
|-----|-----|
| Find short **z** where **Az = 0** | Find secret **s** given **As + e = b** |
| "Find a short preimage" | "Decode with noise" |
| Used for: hash functions, signatures | Used for: encryption, key exchange |

They are **dual** problems — both reduce to hard lattice problems, but from different angles.

### Applications in Cryptography

1. **Collision-resistant hash functions**: Define h(**x**) = **Ax** mod q. Finding a collision means finding **x₁ ≠ x₂** with h(**x₁**) = h(**x₂**), which means **A(x₁ - x₂) = 0** — exactly SIS!

2. **Digital signatures**: Many lattice-based signature schemes (like Dilithium, used in post-quantum standards) rely on SIS-type assumptions.

3. **Commitment schemes**: Binding property often relies on SIS hardness.

### Inhomogeneous SIS (ISIS)

A variant where instead of finding **z** with **Az = 0**, you find short **z** with:

**Az = u (mod q)**

for some target vector **u**. This is equally hard and often more useful in constructions.

### Intuition

Think of it this way: you have a system of linear equations (mod q) with many more unknowns than equations. There are infinitely many solutions, but they form a structured lattice. The "natural" solutions you'd find via Gaussian elimination have large coefficients. Finding one where all coefficients are small (bounded by β) requires essentially searching through the lattice — which is exponentially hard in the dimension.

## LWE

LWE is a computational hardness assumption - we believe certain problems are too hard for any efficient algorithm to solve. It's popular in modern crypto because it is believed to be secure even against quantum computers.

The parameters are:
- n: the dimension of the vector
- m: number of samples givent to the attacker
- q: a modulus (all arithmetic is done modulo q)
- X: an error/noise distribution

The core idea:
Given,
- Random matrix **A** of size m x n (entries mod q)
- Secret vector **s** of length n
- Small error vector **e** from X (this is noise)
- Complete random vector **r**

The LWE assumption says these two things **look the same** to any efficient algorithm:
- The vector (A, As + e)
- The vector (A, r)

In other words: if you give someone A and the product As with some small noise added, they can't tell the difference between that and just random garbage.

### LWE Security

There is no efficient adversary that can reliably tell them apart.
The security is quantified by:
- T — the attacker's running time
- ε — the attacker's "advantage" (probability of guessing correctly beyond 50%)

If the best attack running in time T can only distinguish with advantage ε (very small), then the scheme is (T, ε)-hard.

### LWE Intuition

Think of it like this: multiplying by A is a lossy operation, and adding noise e further scrambles things. Recovering s from As+e is like solving a system of linear equations where every equation has a small random error—this turns out to be extremely hard when the parameters are chosen correctly.

## Regev Encryption

Regev encryption is a type of public-key encryption that is based on the LWE assumption.

Parameters:
- (n, q, χ) — the LWE parameters from before
- p — the plaintext modulus (messages are in ℤₚ, i.e., integers 0 to p-1)
- s — the secret key, a random vector in ℤₙ_q

### Encryption

To encrypt a message μ ∈ ℤₚ:
- Pick a random vector a ∈ ℤₙ_q
- Sample a small error e from χ
- Compute the ciphertext:
```
(a, c) = (a, aᵀs + e + ⌊q/p⌋ · μ)
```

What's happening here:
- aᵀs — inner product of a and secret s (this is the "LWE part")
- + e — add noise to hide information
- + ⌊q/p⌋ · μ — encode the message by scaling it up

The factor ⌊q/p⌋ is crucial: it "lifts" the message into a higher range so it survives the noise.
  
### Decryption

Someone with secret s decrypts by:
- Compute: `c - aᵀs mod q`
- This gives: `e + ⌊q/p⌋ · μ`
- Round to the nearest multiple of ⌊q/p⌋
- Divide by ⌊q/p⌋ to recover μ

VisuaL
```
|-------|-------|-------|-------| ... |-------|
0     ⌊q/p⌋   2⌊q/p⌋  3⌊q/p⌋         (p-1)⌊q/p⌋

      μ=1       μ=2      μ=3           μ=p-1
```

The message μ determines which "slot" you land in. The error e is small, so it just wobbles you around within your slot - rounding recovers which slot you're in.


### Correctness Condition

Decryption works if and only if:
```
|e| < ½ · ⌊q/p⌋
```

If the error is too large, you might "wobble" into the wrong slot and decrypt to the wrong message. The correctness error δ is the probability this happens.

### Additive Homomorphism

This is the magic property that makes Regev encryption useful for PIR:

Given two ciphertexts:
- (a₁, c₁) encrypting μ₁
- (a₂, c₂) encrypting μ₂
Their component-wise sum (a₁ + a₂, c₁ + c₂) decrypts to μ₁ + μ₂!

Why it works:
```
(c₁ + c₂) - (a₁ + a₂)ᵀs 
= (e₁ + ⌊q/p⌋·μ₁) + (e₂ + ⌊q/p⌋·μ₂)
= e₁ + e₂
```

The errors accumulate (e₁ + e₂), so you can only do this a limited number of times before errors grow too large and decryption fails.

### Summary

Key: s <- random vector in ℤₙ_q
Encrypt(μ): (a, aᵀs + e + ⌊q/p⌋ · μ)
Decrypt(a,c): round((c - aᵀs) / ⌊q/p⌋)
Add ciphertexts: (a₁ + a₂, c₁ + c₂) -> decrypts to μ₁ + μ₂

## Ring-LWE

Ring-LWE (Ring Learning With Errors) is a structured variant of LWE that offers significant efficiency improvements while maintaining strong security guarantees.

In standard LWE, we work with:
- A random matrix A ∈ ℤ_q^{n x m}
- A secret vector s ∈ ℤ_q^n
- A small error vector e ∈ ℤ_q^n

The LWE problem is to distinguish (A, A*s + e) from uniform randomness.

Key characteristics:
- Matrix A has no special structure
- Storage O(n*m) elements
- Computation O(n*m) operations for matrix-vector multiplication

### Ring-LWE

Ring-LWE replaces unstructured matrices with polynomial rings:

The Ring: R_q = Z_q[X]/(X^n + 1) where n is a power of two.

Instead of vectors and matrices, we work with polynomials:
- a(x) ∈ R_q^n (a random polynomial)
- s(x) ∈ R_q (the secret polynomial with small coefficients)
- e(x) ∈ R_q (the error polynomial with small coefficients)

The LWE problem becomes: distinguish (A, A*s + e) from uniform randomness.

The Ring-LWE problem is to distinguish (a, a·s + e) from uniform in R_q × R_q.

### Key Differences

| Aspect           | LWE                    | Ring-LWE                         |
|------------------|------------------------|----------------------------------|
| Structure        | Random matrices        | Polynomial rings                 |
| Public key size  | O(n²)                  | O(n)                             |
| Computation      | O(n²) matrix multiply  | O(n log n) via NTT/FFT           |
| Security basis   | Unstructured lattices  | Ideal lattices                   |

### Why Ring-LWE is Faster

Multiplication in R_q = Z_q[x]/(x^n + 1) has special structure:
1. Negacyclic convolution: Multiplying by X^i "rotates" coefficients with sign flips.
2. NTT acceleration: The Number Theoretic Transform (NTT, like FTT for final fields) reduces polynomial multiplication from O(n²) to O(n log n).

A single polynomial a(X) in Ring-LWE implicitly defines an entire nxn matrix in LWE (a circulant-like structure), but we only store n coefficients.

### Security Relationship

Ring-LWE's security relies on the hardness of problems in ideal lattices (lattices with additional algebraic structure). The relationship to LWE security:
- **Worst-case to average-case**: Ring-LWE has quantum reductions from worst-case problems on ideal lattices (SVP in ideal lattices)
- **More structure = potential weakness?**: The ring structure theoretically gives attackers more to exploit, but no practical attacks have emerged
- **Practical security**: Ring-LWE is considered secure for appropriate parameters, and is used in post-quantum standards like Kyber/ML-KEM