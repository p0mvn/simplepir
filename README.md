# SimplePIR

A Rust implementation of SimplePIR built from first principles.

SimplePIR is based on a standard square-root PIR construction that uses Regev encryption to achieve sublinear communication complexity.

What this means is that records are stored as a matrix of size √N × √N, and the client can retrieve a record by selecting a column and then a row from that column.

The client starts by sending an encrypted query to the server where the choice of the column is hidden.

The server computes the answer by multiplying the database matrix by the query vector.

The client Regev-decrypts the answer and extracts the record from the answer.

Additionally, there is a preprocessing step where the server computes the matrix-vector product of the database matrix and the client hint matrix. The hint is reused for all clients. This helps for client to query the hint only once and then reuse it for all queries. Thus, amortizing the cost across queries.

The setup does not support updates. If an update is needed, the server needs to recompute the hint and retransmit it to all clients.

Communication: O(N^(1/d) · F^(d-1))  where d = dimension parameter
Server operations: O(N · F^(d-1)) homomorphic ops

## Benchmark Results

See `benches/results` for benchmark results.

A setup that is near-identical to the SimplePIR paper was benchmarked [here](https://github.com/p0mvn/simplepir/pull/1). The results has shown to be comparable.

## Implemented Optimizations

- Preprocessing
  * Instead of transmitting A as part of hint in the setup process, transmit a seed that was used to generate A, letting client regenerate A locally from the seed using ChaCha20 PRG.
  * Use rayon for parallelization of matrix operations. There were many matrix operations with loop iterations independent of each other, so we can parallelize them using rayon. In benchmarks, this was only helpful for hint computation. In online operations (i.e. server answer) it only hurt performance. The reason is that the rayon overhead exceeds the benefit of the parallelization. Generally, parallelization is only worth it if the work per thread is much greater than the thread overhead (i.e Total Work Time >> Thread Overhead (~50 µs))

- General
  * Use u32 instead of u64 for all arithmetic operations. Our parametrization allows choosing q = 2^32, which fits in a u32. By using u64, we were wasting half the bits of precision. Smaller parameters allow for smaller data types that fit better in cache, improving memory bandwidth utilization.

# Future Optimizations

- Cache tiling. Matrix A is accessed column-wise in the inner loop, but stored row-wise in memory. Every A[k,j] access jumps 1024 elements (4KB) — terrible cache locality. Implementation was attempted and has shown 53% speedup at 100K records (at 1K overhead made it slightly lower). The implementation was omitted due to complexity but it would be worthwhile to implement for production.

- SIMD vectorization. We could use SIMD vectorization to speed up the matrix operations. This would be especially useful for the server answer operation, where we could vectorize the multiplication of the matrix by the query vector. We did not implement this due to complexity and since Rust compiler may auto-vectorize loops with specific compilation flags.
