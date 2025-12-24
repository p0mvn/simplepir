# PIR Theory

## Simple PIR

The expansion factor (F) is a measure of how much larger a ciphertext becomes compared to the original plaintext when you encrypt data.
Breaking it down:
- Plaintext: ℓ bits (your original message)
- Ciphertext: ℓ · F bits (the encrypted result)

So if F = 2, your encrypted data is twice as large as the original. If F = 10, it's ten times larger.

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


## PIR w/ Hints

Standard PIR: Client wants to retrieve item i from a database without the server learning which item. Every query requires heavy computation.

PIR with Hints: The server does expensive preprocessing once, producing "hints" that make subsequent queries much cheaper.

```
┌─────────────────────────────────────────────────────────────┐
│                    OFFLINE PHASE (once)                     │
│  Server runs Setup(db) → (hint_s, hint_c)                   │
│    • hint_s: server keeps locally                           │
│    • hint_c: sent to client (reusable for all queries)      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 ONLINE PHASE (per query)                    │
│  Client: Query(i) → (st, qu)     [fast!]                    │
│  Server: Answer(db, hint_s, qu) → ans    [fast!]            │
│  Client: Recover(st, hint_c, ans) → d_i                     │
└─────────────────────────────────────────────────────────────┘
```

### Four Routines

1. Setup(db) → (hint_s, hint_c)
   * Server runs offline
2. Query(i) → (st, qu)
   * Client runs
3. Answer(db, hint_s, qu) → ans
   * Server runs
4. Recover(st, hint_c, ans) → d_i
   * Client runs

### Key Properties

1. Hints are small

Both hins are sublinear in the database size

```
|hint_s|, |hint_c| = o(|db|)
```

e.g., if db is 1GB, hints might be 1MB

2. Hints are reusable

- Same hint for all clients — server computes once, distributes to everyone
- Same hint for all queries — client keeps hint_c and reuses it forever

3.  Non-triviality Requirement

Total communication must be less than just downloading the whole database:
```
|hint_c| + |qu| + |ans| ≪ |db|
```

### Correctness

The scheme has correctness error δ if:
```
Pr[client recovers correct record d_i] ≥ 1 - δ
```

This accounts for the small probability of decryption errors (from Regev encryption noise accumulating).


### Security Definition

Intuition: The query qu reveals nothing about which index i the client wants.

Formal definition: For any two indices i and j, the queries are computationally indistinguishable:
```
{Query(i).qu} ≈ {Query(j).qu}
```

More precisely, (T, ε)-secure means: any adversary running in time T can distinguish queries for index i vs index j with advantage at most ε.

Why this matters: Even if the server is malicious and tries to figure out what you're querying, they can't do better than random guessing.


## Simple PIR

## How It Works

It uses Regev encryption with the database arranged as a √N × √N matrix. The key insight is that the LWE matrix A serves as the client hint, and the server only needs to do a matrix-vector multiplication to answer queries.

### Construction

**Parameters:**
- Database size N
- LWE parameters (n, q, χ)
- Plaintext modulus p ≪ q
- LWE matrix A ∈ ℤ_q^{√N × n} (sampled via hash function in practice)
- Database: N values in ℤ_p, represented as matrix db ∈ ℤ_p^{√N × √N}
- Scaling factor: Δ := ⌊q/p⌋

---

**Setup(db ∈ ℤ_p^{√N × √N}) → (hint_s, hint_c)**

```
hint_s ← ⊥                      // server stores nothing extra
hint_c ← db · A ∈ ℤ_q^{√N × n}  // client hint = database × LWE matrix
return (hint_s, hint_c)
```

---

**Query(i ∈ [N]) → (st, qu)**

```
1. Parse i as (i_row, i_col) ∈ [√N]²

2. Sample fresh secrets:
   s ←_R ℤ_q^n          // random secret vector
   e ←_R χ^{√N}         // error vector from noise distribution

3. Build encrypted unit vector:
   u_{i_col} ← [0, 0, ..., 1, ..., 0]   // 1 at position i_col
   qu ← A·s + e + Δ·u_{i_col} ∈ ℤ_q^{√N}

4. return (st, qu) ← ((i_row, s), qu)
```

The query `qu` is a Regev encryption of the column selector, with secret `s` kept for decryption.

---

**Answer(db ∈ ℤ_p^{√N × √N}, hint_s, qu ∈ ℤ_q^{√N}) → ans**

```
ans ← db · qu ∈ ℤ_q^{√N}   // matrix-vector multiply
return ans
```

This is the only online server computation: one matrix-vector product.

---

**Recover(st, hint_c ∈ ℤ_q^{√N × n}, ans ∈ ℤ_q^{√N}) → d**

```
1. Parse st as (i_row, s)

2. Decrypt the desired row:
   d̂ ← ans[i_row] − hint_c[i_row, :] · s  ∈ ℤ_q
   
   where:
   - ans[i_row] is component i_row of the answer
   - hint_c[i_row, :] is row i_row of the hint matrix

3. Round to recover plaintext:
   d ← Round_Δ(d̂) / Δ  ∈ ℤ_p
   
   (round d̂ to nearest multiple of Δ, then divide by Δ)

4. return d
```

---

**Why This Works:**

Expanding the decryption:
```
ans[i_row] = (db · qu)[i_row]
           = db[i_row, :] · qu
           = db[i_row, :] · (A·s + e + Δ·u_{i_col})
           = db[i_row, :] · A·s  +  db[i_row, :] · e  +  Δ · db[i_row, i_col]
             └─────────────┬─────────────┘              └────────┬────────┘
                    "noise" terms                         scaled message
```

When we subtract `hint_c[i_row, :] · s = (db · A)[i_row, :] · s = db[i_row, :] · A · s`:

```
d̂ = ans[i_row] − hint_c[i_row, :] · s
  = db[i_row, :] · e  +  Δ · db[i_row, i_col]
    └──────┬──────┘      └────────┬────────┘
     small error          scaled target value
```

Rounding recovers `db[i_row, i_col]` as long as the error term is small enough (< Δ/2).

### Cost Breakdown

| Phase                | Who            | Cost                                 |
|----------------------|----------------|--------------------------------------|
| Offline (once)       | Server         | 2n·N operations in ℤ_q               |
| Offline (once)       | Client download| n·√N elements (the hint)             |
| Online (per query)   | Client upload  | √N elements                          |
| Online (per query)   | Server compute | 2N operations                        |
| Online (per query)   | Client download| √N elements                          |

#### Understanding the Costs

To understand these costs, we need to see how SimplePIR structures the data and query process.

**Database Structure:**

The database (N records) is arranged as a √N × √N matrix:

```
         col 0   col 1   col 2  ...  col √N-1
       ┌───────┬───────┬───────┬───┬─────────┐
row 0  │ d₀    │ d₁    │ d₂    │...│ d_{√N-1}│
row 1  │ d_{√N}│ ...   │       │   │         │
  ⋮    │       │       │       │   │         │
row √N-1│      │       │       │   │ d_{N-1} │
       └───────┴───────┴───────┴───┴─────────┘
```

To fetch record at position (row `r`, column `c`), the client will:
1. Ask the server for an encrypted copy of column `c`
2. Locally extract row `r` from that column

**Client Hint Download (n·√N elements):**

The hint is the LWE matrix **A** of size √N × n. This matrix is public/shared and lets the client build compact encrypted queries. Without A, each Regev ciphertext would need to include its own random vector, making queries much larger.

Why √N × n? Each of the √N database rows needs its own "encryption slot," and n is fixed by LWE security requirements.

**Client Upload (√N elements):**

The client creates an encrypted selection vector to pick column `c`:

```
selection vector = [0, 0, ..., 1, ..., 0]  (1 at position c)
                    └──────√N entries──────┘
```

Using Regev encryption with the shared matrix A:
```
query = A·s + e + ⌊q/p⌋·[0,0,...,1,...,0]
```

The client only uploads the ciphertext part (√N elements), not A (already known to server). Why √N? One encrypted bit for each column in the database matrix.

**Server Compute (2N operations):**

The server computes a matrix-vector multiplication:

```
answer = DB × query
         (√N × √N)  (√N × 1)  =  (√N × 1)
```

For each of the √N output elements:
- √N multiplications (one per column)
- √N - 1 additions (to sum them up)
- ≈ 2√N operations per output

Total: √N outputs × 2√N ops = **2N operations**

Due to Regev's additive homomorphism, this matrix multiply "selects" column c while everything stays encrypted:

```
DB × encrypted([0,0,1,0,...]) = encrypted(column c)
```

**Client Download (√N elements):**

The server's answer is the encrypted column the client asked for. That's √N entries—one for each row in the selected column. The client decrypts this column and extracts the specific row they wanted.

**Offline Server Work (2n·N operations):**

During setup, the server precomputes Aᵀ × DB (or similar preprocessing). This involves n·√N output elements, each requiring 2√N operations, totaling 2n·N operations. This is expensive but done once and amortized over all future queries.

**Why √N Everywhere?**

The 2D matrix layout is the key insight. Communication scales with the side length (√N), while server work scales with the area (N). This achieves sublinear communication with only linear server computation—essentially optimal since the server must at least read the entire database once.

### Concrete Parameters
For 128-bit security:
n = 2¹⁰ = 1024 (LWE dimension)
q = 2³² = 4 billion (modulus, fits in a 32-bit integer)

### Security & Correctness

If the underlying LWE problem is (T, ε)-hard, then SimplePIR is:
- (T - O(√N), 2ε)-secure — almost as secure as LWE itself
- Has correctness error δ (from Regev decryption)

### Key Takeaway

The server's online work is just 2N integer operations — essentially one pass over the database doing additions/multiplications. This is nearly optimal (you can't do better than reading the whole database once), which is why SimplePIR achieves the highest throughput.

```
Communication:     √N upload + √N download   ← sublinear!
Server compute:    2N ops                    ← linear (optimal)
Hint size:         n·√N                      ← sublinear
```

### Simple PIR Technical Ideals

Builds on a classic PIR approach:

1. Database as matrix: Store N records as a √N × √N matrix D
2. Query as encrypted unit vector: Client encrypts a selection vector with a 1 at the desired column
3. Server computes matrix-vector product: D × encrypted_query → encrypted column
4. Client decrypts: Recovers the target column, extracts the desired row

Basic cost: 2√N ciphertext elements exchanged, N ciphertext operations on the server.

Key Insight: Regev Encryption Structure

SimplePIR instantiates this with Regev encryption, exploiting three properties:

| Property              | Observation                                                        | Benefit                    |
|-----------------------|--------------------------------------------------------------------|----------------------------|
| Message-independent A | The LWE matrix A doesn't depend on what's being encrypted          | A can be generated ahead of time |
| Reusable A            | Same A can encrypt many messages securely (with fresh s, e each time) | All clients share one A    |
| Pseudorandom A        | A can be derived from a short seed via PRG                        | Compress A to a tiny seed  |

### The Three Optimizations

**1. Preprocessing \( D \cdot A \)**

- **Offline:** Precompute \( D \cdot A \) instead of performing both \( (D \cdot A, D \cdot c) \) online.
    - Requires \( 2n \cdot N \) operations (for computing \( D \cdot A \)).
- **Online:** Only compute \( D \cdot c \).
    - Requires just \( 2N \) operations.
- **Result:** Approximately 99.9% of the server's work is moved offline (since \( n \approx 1024 \)).

**2. Shared Hint Across All Clients**

- The precomputed \( D \cdot A \) serves as a *universal hint*:
    - Computed **once** by the server.
    - Sent to **all clients**.
    - Reused for every query.
    - Cost amortized over all clients and queries.

**3. Compress \( A \) with Pseudorandomness**

- Instead of storing or sending the full matrix \( A \):
    - Derive \( A = \text{Hash}(\text{seed}, \text{counter}) \) using a random oracle.
    - Only store/communicate the small seed.
- This results in massive savings in bandwidth and storage.

Visual:
```
CLASSIC APPROACH:
  Client sends: (A, c)           ← large!
  Server computes: (D·A, D·c)    ← all online

SIMPLEPIR:
  Offline:  Server precomputes D·A, sends as hint
            A compressed to seed
  
  Online:   Client sends: c only  ← small (√N elements)
            Server computes: D·c  ← fast (2N ops)
            Client receives: D·c  ← small (√N elements)
```

Security & Correctness
- Security: Follows from LWE hardness + security of Regev encryption with reused A
- Correctness: Follows from Regev's additive homomorphism + the square-root PIR template

### Practical Extensions

**Large records:** Stack multi-element records vertically in columns. One query retrieves an entire column, reconstructing the full record. Costs scale by √d for records of size d elements.

**Batch PIR:** To fetch k records efficiently, partition the database into k chunks. If desired records fall into different chunks, server work stays at N (not k·N). Collisions handled via redundant queries or best-effort recovery.

## To Look Into

- [Regular LWE](https://arxiv.org/pdf/2401.03703)
  - How does it differ from ring? Claimed to be much simpler
- [Ring-LWE](https://eprint.iacr.org/2014/725.pdf)
- [INSPIRE: IN-Storage Private Information REtrieval via Protocol
and Architecture Co-design](https://dl.acm.org/doi/pdf/10.1145/3470496.3527433)
  * SSD-based PIR
- On minimizing the database updates / offline work:
  - Dmitry Kogan and Henry Corrigan-Gibbs. Private blocklist lookups with Checklist. In USENIX Security, 2021.
  - Yiping Ma, Ke Zhong, Tal Rabin, and Sebastian Angel. Incremental offline/online PIR. In USENIX Security, 2022.
- Kushilevitz and Ostrovsky’s “square-root” PIR template. Base of Simple PIR.


