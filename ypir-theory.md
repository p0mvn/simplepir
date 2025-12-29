# YPIR Theory

## Main Contributions

### High-throghput with silent pre-processing

The YPIR protocol can be viewed as appending a lightweight post-processing step to DoublePIR to “compress” the DoublePIR response.

When retrieving a single bit from a 32 GB database, YPIR achieves a throughput of 12.1 GB/s, which is 97% of the throughput of SimplePIR (and 83% of the memory bandwidth of the machine).

For database sizes ranging from 1 GB to 32 GB, the YPIR response size is the same as that in DoublePIR, 9–37× shorter than the response size in SimplePIR.

On the flip side, YPIR queries are 1.8–3× larger than those in DoublePIR, 3–7× larger than SimplePIR.

YPIR achieves 97% of the throughput of one of the fastest single-server PIR schemes while fully eliminating all offline communication and only incurring a modest increase in query size

### Faster server pre-processing

Reduces the offline preprocessing cost by a factor of 𝑛/log𝑛 compared to Simple PIR

### Cross-client batching

Cross-client batching. The throughput of the SimplePIR family of protocols is memory-bandwidth limited. This means that the server can only process one client at a time. However, if the server can process multiple clients at once, it can achieve higher throughput. This is achieved by batching the clients' queries together and processing them in parallel.

With just 4 clients, cross-client batching improves the effective server throughput for a protocol like SimplePIR by a factor of 1.4× to 17 GB/s; applied to YPIR, we achieve an effective throughput of 16 GB/s.


## Limitation

The main limitation of YPIR is the larger query sizes compared to SimplePIR and DoublePIR. Specifically,
a YPIR query is 1.8–3× larger than a DoublePIR query (for an 8 GB database, YPIR queries are 1.5 MB while
DoublePIR queries are 724 KB) and 3–7× larger than a SimplePIR query.

This is because the post-processing step in YPIR requires communicating a “packing key” as part of the query. If the application setting has a small, fixed communication budget, YPIR may not be appropriate; for example, for a 32 GB database, the minimum YPIR query size is 1.1 MB.

## Overview of the Protocol

### Response Packing

Eliminate DoublePIR's offline hint by compressing the server's response using Ring LWE (RLWE).

**Why use RLWE when SimplePIR moved away from it?**

SimplePIR achieved its 40× speedup by avoiding Ring-LWE for the core database computation—prior schemes like SealPIR used expensive NTT/FFT polynomial operations on *every database element*, which was catastrophically slow. YPIR doesn't contradict this insight. Instead, it uses RLWE *only* for the final response packing step, which operates on √N elements (the response), not N elements (the database). For an 8GB database, this means RLWE is applied to ~90,000 elements rather than ~8 billion. The database scan still uses SimplePIR's fast 32-bit integer operations. YPIR gets the best of both worlds: SimplePIR's throughput for the heavy lifting, plus RLWE's compression power applied surgically to the small response.

**Clarification: Ring-LWE vs LWE efficiency**

There's a common claim that "Ring-LWE is faster than LWE"—and this is true when comparing equivalent cryptographic operations. Ring-LWE compresses an n×n matrix into a single polynomial, reducing storage from O(n²) to O(n) and computation from O(n²) to O(n log n) via NTT. For encryption, key exchange, or any task where you'd otherwise do full matrix-vector multiplication, Ring-LWE wins decisively.

But SimplePIR's insight was different: **for PIR, you don't need to do cryptographic operations on the database at all**. The database is public—you only need crypto to hide *which element* you're accessing. Prior RLWE-based PIR schemes (like SealPIR) treated each database entry as a polynomial and performed polynomial multiplication on every element:

| Approach | Operation per DB element | Cost |
|----------|-------------------------|------|
| SealPIR (RLWE-native) | Polynomial multiplication | O(n log n) via NTT |
| SimplePIR (scalar) | Integer multiply-add | O(1) |

Even though NTT is the optimal way to multiply polynomials, **not multiplying polynomials** is faster still. SimplePIR's core operation is just `result += db_entry × query_component`—a single 32-bit multiply and add (~1-3 CPU cycles) versus thousands of cycles for NTT-based polynomial multiplication.

So the 40× speedup comes from avoiding crypto overhead on database elements entirely, not from LWE being inherently faster than Ring-LWE. YPIR applies RLWE only where its compression power matters (the small response), while keeping SimplePIR's raw integer throughput for the database scan.

**Key Concepts**

- Ring LWE advantage: Works over polynomial ring:
```
R = Z[x]/(x^d + 1)
```
where d is a power of two

**Vanilla LWE:** Encrypting a single value $\mu \in \mathbb{Z}_p$ requires $(n+1)$ elements in $\mathbb{Z}_q$.

**Ring LWE:** Encrypting a ring element $\mu \in R_p$ requires only 2 elements in $R_q$.

#### Why LWE needs (n+1) elements vs RLWE needs 2 elements

**LWE ciphertext structure:**
$$\text{ct} = (\mathbf{a}, b) \in \mathbb{Z}_q^n \times \mathbb{Z}_q$$

where $\mathbf{a}$ is a random vector (n elements) and $b = \langle \mathbf{a}, \mathbf{s} \rangle + e + \lfloor q/p \rfloor \cdot \mu$ (1 element). Total: **n + 1 elements**.

**RLWE ciphertext structure:**
$$\text{ct} = (a, b) \in R_q \times R_q$$

where $a$ is a random polynomial and $b = a \cdot s + e + \lfloor q/p \rfloor \cdot \mu$. Total: **2 ring elements**.

Each ring element in $R_q$ has $d$ coefficients. The key insight is that RLWE encrypts $d$ values at once (as polynomial coefficients) using only $2d$ total coefficients, whereas $d$ separate LWE ciphertexts would require $d(n+1)$ coefficients.

When $n = d$: compression factor is $\frac{d(d+1)}{2d} = \frac{d+1}{2} \approx 512\times$ for $d = 1024$.

This reduces ciphertext expansion from $(n+1)\log q / \log p$ to $2\log q / \log p$—roughly a $1000\times$ improvement for $n \approx 2^{10}$.

**The LWE-to-RLWE Packing Technique**

The technique takes $d$ LWE ciphertexts

$$
ct_1, \ldots, ct_d \in \mathbb{Z}_q^{d+1}
$$

encoding messages 

$$
\mu_1, \ldots, \mu_d
$$

and packs them into a single RLWE ciphertext encrypting the polynomial

$$
\mu(x) = \mu_1 + \mu_2 x + \cdots + \mu_d x^{d-1}
$$

**Compression ratio:** $d(d+1)$ elements → $2d$ elements, yielding $\frac{d+1}{2}$ reduction

Practical impact:
- Response size reduction: 9–37× shorter than SimplePIR
- Query size increase: 1.8–3× larger than DoublePIR, 3–7× larger than SimplePIR

**Trade-off**: Query must include a "packing key" (RLWE key-switching matrices), increasing query size.

Most of the transformation cost can be moved to offline preprocessing (query-independent), achieving 9× reduction in online computation.

---

### The CDKS Transformation (LWE-to-RLWE Packing)

This is how YPIR compresses the DoublePIR response. The technique comes from Chen-Dai-Kim-Song [CDKS21].

#### The Problem

After DoublePIR, the server has **d separate LWE ciphertexts**, each encrypting one value:

```
ct₀ encrypts μ₀    (requires d+1 numbers)
ct₁ encrypts μ₁    (requires d+1 numbers)
...
ct_{d-1} encrypts μ_{d-1}  (requires d+1 numbers)

Total: d × (d+1) numbers
```

We want to compress these into **one RLWE ciphertext** that encrypts all values at once:

```
RLWE ciphertext encrypts μ₀ + μ₁x + μ₂x² + ... + μ_{d-1}x^{d-1}

Total: 2d numbers
```

That's a compression factor of $(d+1)/2 \approx 500\times$ for $d = 1024$.

#### Why This Is Tricky

You can't just "add up" the LWE ciphertexts. Each ciphertext encrypts a single scalar value, but we need a polynomial where each coefficient is a different value.

The key insight: in RLWE, multiplying by $x$ **shifts coefficients**:
- If $\mu = a + bx + cx^2$, then $x \cdot \mu = ax + bx^2 + cx^3$

So if we could somehow:
1. Take ct₀ (encrypting μ₀) and make it encrypt just the constant term
2. Take ct₁ (encrypting μ₁) and make it encrypt the $x$ coefficient
3. Take ct₂ (encrypting μ₂) and make it encrypt the $x^2$ coefficient
4. Add them all up...

We'd get an encryption of $\mu_0 + \mu_1 x + \mu_2 x^2 + ...$

#### The Tool: Automorphisms

An **automorphism** is a function that "shuffles" polynomial coefficients in a specific pattern.

The automorphism $\tau_\ell$ replaces $x$ with $x^\ell$:
$$\tau_\ell(p(x)) = p(x^\ell)$$

**Simple example** (with $d=4$, so we work mod $x^4 + 1$):

If $p(x) = 1 + 2x + 3x^2 + 4x^3$, then:
- $\tau_3(p) = p(x^3) = 1 + 2x^3 + 3x^6 + 4x^9$
- Since $x^4 = -1$ in our ring: $x^6 = -x^2$ and $x^9 = -x$
- Result: $\tau_3(p) = 1 - 4x - 3x^2 + 2x^3$

The coefficients got **permuted** (and some signs flipped).

**The magic**: We can apply automorphisms to *encrypted* polynomials without decrypting! This requires a special "automorphism key" that the client provides. It adds a bit of noise, but the result is an encryption of $\tau_\ell(\mu)$ under the same secret key.

#### How Packing Works (Simplified)

The CDKS algorithm uses a **divide-and-conquer** approach:

```
Step 1: Start with d=4 ciphertexts
   ct₀(μ₀)    ct₁(μ₁)    ct₂(μ₂)    ct₃(μ₃)

Step 2: Pair them up and combine
   "even" = combine(ct₀, ct₂)  →  encrypts (μ₀ + μ₂x²)
   "odd"  = combine(ct₁, ct₃)  →  encrypts (μ₁ + μ₃x²)

Step 3: Use automorphism to shift "odd" and combine
   Final = even + x·odd + automorph_magic
         = encrypts (μ₀ + μ₁x + μ₂x² + μ₃x³)
```

The "automorph_magic" ensures that adding even and odd doesn't cause interference between coefficients. It's like interleaving two signals without them overlapping.

For $d = 2048$, this takes $\log_2(d) = 11$ rounds of combining.

#### What the Client Must Provide

For this to work, the client must send **automorphism keys** (also called the "packing key"):
- One key for each type of automorphism used ($\log_2(d)$ keys total)
- Each key is an RLWE encryption of $\tau(s)$ under $s$

This is why YPIR queries are larger than DoublePIR queries—they include the packing key.

#### Security Note: Circular Security

The packing key encrypts $\tau(s)$ (a function of the secret key) under $s$ itself. This is called "key-dependent" or "circular" encryption.

**Circular security** assumes this doesn't leak information about $s$. This is a standard assumption used in all practical FHE schemes—no attacks are known.

---

## The YPIR Protocol

YPIR combines **DoublePIR** with **LWE-to-RLWE packing**:

```
Database D → SimplePIR → DoublePIR → CDKS Packing → Small RLWE response
```

### Protocol Parameters

YPIR uses **two sets of lattice parameters** (one for each pass):

| Pass | Ring | Dimension | Modulus | Purpose |
|------|------|-----------|---------|---------|
| **SimplePIR** | $R_{d_1}$ | $d_1 = 2^{10}$ | $q_1 = 2^{32}$ | Linear scan over database |
| **DoublePIR** | $R_{d_2}$ | $d_2 = 2^{11}$ | $q_2 \approx 2^{56}$ | Recursion + packing |

Additional parameters:
- Decomposition base $z$ (for gadget decomposition in packing)
- Intermediate modulus $p$
- $\kappa = \lceil \log \tilde{q}_1 / \log p \rceil$ (number of base-$p$ digits)

### The Four Algorithms

#### 1. DBSetup(D) — Server Preprocessing

**Input**: Database $D \in \mathbb{Z}_N^{\ell_1 \times \ell_2}$

**Computes**:
1. Generate structured matrices $A_1, A_2$ from random seeds $\mathbf{a}_1, \mathbf{a}_2$ using negacyclic structure
2. $H_1 = G^{-1}_{d_1,p}(\lfloor A_1 D \rceil_{q_1, \tilde{q}_1})$ — "SimplePIR hint" (decomposed)
3. $H_2 = A_2 \cdot H_1^T$ — "DoublePIR hint"

**Output**: 
- Public params $\text{pp} = (\mathbf{a}_1, \mathbf{a}_2)$ (just seeds!)
- Server state $\text{dbp} = (D, H_1, H_2)$

#### 2. Query(pp, idx) — Client Query Generation

**Input**: Target index $(i_1, i_2)$

**Steps**:
1. **Key generation**: 
   - Sample secret keys $s_1 \leftarrow \chi_1$, $s_2 \leftarrow \chi_2$
   - Compute packing key $\text{pk} \leftarrow \text{CDKS.Setup}(s_2, z)$

2. **Encode indices**: 
   - Decompose $i_j = \alpha_j d_j + \beta_j$ (block index + offset within block)
   - Create RLWE encoding $c_j$ that encrypts indicator for row $i_1$ / column $i_2$:
     $$c_j = \text{Coeffs}(s_j \mathbf{a}_j + \mathbf{e}_j + \Delta_j \mu_j)$$
   - where $\mu_j = x^{\beta_j} \mathbf{u}_{\alpha_j}$ encodes the target position

**Output**: 
- Query $\mathbf{q} = (\text{pk}, c_1, c_2)$
- Secret query key $\text{qk} = (s_1, s_2)$

#### 3. Answer(dbp, q) — Server Response Computation

**Input**: Database state $(D, H_1, H_2)$ + query $(\text{pk}, c_1, c_2)$

**Steps**:

1. **SimplePIR step**: 
   $$T = g_p^{-1}(\lfloor c_1^T D \rceil_{q_1, \tilde{q}_1})$$
   This gives (encrypted) row $i_1$ of the database, decomposed into base-$p$ digits.

2. **DoublePIR step**: Combine precomputed hints with query:
   $$C = (d_2^{-1} \mod q_2) \cdot \begin{bmatrix} H_2 & A_2 \\ T & c_2 \end{bmatrix} \cdot \begin{bmatrix} c_2^T \\ H_1^T & c_2^T \\ T^T \end{bmatrix}$$
   This produces $\kappa(d_1 + 1)$ LWE ciphertexts (a matrix $C$).

3. **Pack encodings**: 
   - Split $C$ into blocks $C_1, \ldots, C_\rho$ where $\rho = \lceil \kappa(d_1+1)/d_2 \rceil$
   - For each block: $\tilde{c}_i \leftarrow \text{CDKS.Pack}(\text{pk}, C_i)$

4. **Modulus switching**: Reduce ciphertext size for transmission

**Output**: $\text{resp} = \rho$ small RLWE ciphertexts

#### 4. Extract(qk, resp) — Client Decryption

**Input**: Secret keys $(s_1, s_2)$ + response

**Steps**:
1. **Decrypt RLWE**: For each ciphertext, compute $v_i = \lfloor -s_2 c_{i,1} \rceil + c_{i,2}$
2. **Round to plaintext**: $v_i \leftarrow \lfloor v_i \rceil_{\tilde{q}_{2,2}, p}$
3. **Reconstruct LWE ciphertext**: Reassemble from coefficients using gadget matrix $G_{d_1+1,p}$
4. **Final decryption**: $\mu' = [-\text{Coeffs}(s_1) \mid 1] \cdot c'$
5. **Round to record**: $\mu = \lfloor \mu' \rceil_{\tilde{q}_1, N}$

**Output**: Database element $D[i_1, i_2]$

### Visual Summary

```
        ℓ₂ columns
    ┌─────────────────┐
    │                 │
ℓ₁  │    Database D   │ × c₁ (query) → SimplePIR output (row i₁)
rows│                 │
    └─────────────────┘
           ↓
    ┌─────────────────┐
    │   DoublePIR     │ × c₂ (query) → LWE ciphertexts C
    │   (with hints)  │
    └─────────────────┘
           ↓
    ┌─────────────────┐
    │   CDKS.Pack     │ → ρ RLWE ciphertexts (compressed!)
    └─────────────────┘
```

The striped/shaded components ($H_1$, $H_2$) are **precomputed** and query-independent.

### Important Properties

**Silent Preprocessing**: The random matrices $A_1, A_2$ can be derived from a random oracle (hash function). Public parameters are just database dimensions—no large downloads needed.

**Arbitrary Dimensions**: The scheme handles databases where dimensions aren't exact multiples of $d_1, d_2$ by truncating the structured matrices (not padding the database).
