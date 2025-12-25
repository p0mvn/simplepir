use rand::Rng;

use crate::{
    matrix_database::MatrixDatabase,
    params::LweParams,
    pir::{Answer, ClientHint, LweMatrix, Query},
};

/// Server state
pub struct PirServer {
    db: MatrixDatabase,
    a: LweMatrix,
}

impl PirServer {
    /// SimplePIR Setup: compute hint_c = DB · A
    ///
    /// Returns (A, hint_c) where:
    /// - A is shared/public (√N × n)
    /// - hint_c is sent to client (db.rows × n)
    /// - Server stores nothing extra (hint_s = ⊥)
    pub fn setup(self, params: &LweParams, rng: &mut impl Rng) -> (LweMatrix, ClientHint) {
        // A ∈ ℤ_q^{√N × n}
        let a = LweMatrix::random(self.db.cols, params.n, rng);

        // hint_c = DB · A ∈ ℤ_q^{db.rows × n}
        let hint_c = self.compute_hint();

        (a, hint_c)
    }

    /// Matrix multiplication: DB · A
    /// (db.rows × db.cols) · (db.cols × n) → (db.rows × n)
    pub fn compute_hint(&self) -> ClientHint {
        assert_eq!(self.db.cols, self.a.rows, "Inner dimensions must match");

        let rows = self.db.rows;
        let cols = self.a.cols; // n
        let inner = self.db.cols; // √N

        let mut data = vec![0u64; rows * cols];

        for i in 0..rows {
            for j in 0..cols {
                let mut sum = 0u64;
                for k in 0..inner {
                    // hint_c[i,j] += db[i,k] * A[k,j]
                    let db_val = self.db.data[i * self.db.cols + k];
                    let a_val = self.a.get(k, j);
                    sum = sum.wrapping_add(db_val.wrapping_mul(a_val));
                }
                data[i * cols + j] = sum;
            }
        }

        ClientHint { data, rows, cols }
    }

    /// Answer: compute DB · query
    pub fn answer(&self, query: &Query) -> Answer {
        Answer(self.db.multiply_vec(&query.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_database::MatrixDatabase;

    #[test]
    fn test_compute_hint_small_matrix() {
        // Create a 2×2 database (4 records of 1 byte each)
        // Layout:
        //   col0  col1
        //   1     2
        //   3     4
        let records: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        assert_eq!(db.rows, 2);
        assert_eq!(db.cols, 2);

        // Create A matrix (2×2 for n=2)
        // A = [[5, 6],
        //      [7, 8]]
        let a = LweMatrix {
            data: vec![5, 6, 7, 8],
            rows: 2,
            cols: 2,
        };

        let server = PirServer { db, a };

        let hint = server.compute_hint();

        // hint_c = DB · A
        // [[1, 2],    [[5, 6],     [[1*5+2*7, 1*6+2*8],     [[19, 22],
        //  [3, 4]]  ·  [7, 8]]  =   [3*5+4*7, 3*6+4*8]]  =   [43, 50]]

        assert_eq!(hint.rows, 2);
        assert_eq!(hint.cols, 2);
        assert_eq!(hint.data, vec![19, 22, 43, 50]);
    }

    #[test]
    fn test_compute_hint_identity_matrix() {
        // When A is identity, hint_c should equal DB (useful sanity check)
        let records: Vec<Vec<u8>> = vec![vec![10], vec![20], vec![30], vec![40]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // Identity matrix A = I₂
        let a = LweMatrix {
            data: vec![1, 0, 0, 1],
            rows: 2,
            cols: 2,
        };

        let server = PirServer { db, a };

        let hint = server.compute_hint();

        // DB · I = DB
        // DB layout: [[10, 20], [30, 40]]
        assert_eq!(hint.data, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_compute_hint_rectangular() {
        // DB: 2×2, A: 2×3 → hint_c: 2×3
        // Tests non-square output (realistic case where n ≠ √N)
        let records: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // A: 2×3
        // [[1, 2, 3],
        //  [4, 5, 6]]
        let a = LweMatrix {
            data: vec![1, 2, 3, 4, 5, 6],
            rows: 2,
            cols: 3,
        };

        let server = PirServer { db, a };

        let hint = server.compute_hint();

        // [[1, 2],    [[1, 2, 3],     [[1*1+2*4, 1*2+2*5, 1*3+2*6],     [[9, 12, 15],
        //  [3, 4]]  ·  [4, 5, 6]]  =   [3*1+4*4, 3*2+4*5, 3*3+4*6]]  =   [19, 26, 33]]

        assert_eq!(hint.rows, 2);
        assert_eq!(hint.cols, 3);
        assert_eq!(hint.data, vec![9, 12, 15, 19, 26, 33]);
    }
}
