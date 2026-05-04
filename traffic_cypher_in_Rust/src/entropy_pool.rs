use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// Rolling entropy pool that aggregates entropy from the last N frames.
pub struct EntropyPool {
    buffer: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl EntropyPool {
    /// Create a new pool that holds the last `capacity` frames of entropy.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Add new frame entropy to the pool, evicting the oldest if full.
    pub fn push(&mut self, entropy: Vec<u8>) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(entropy);
    }

    /// Produce a 32-byte digest of the entire pool.
    /// Concatenates all buffered entropy and SHA-256 hashes the result.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in &self.buffer {
            hasher.update(entry);
        }
        hasher.finalize().into()
    }

    /// Number of frames currently in the pool.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_rolling_eviction() {
        let mut pool = EntropyPool::new(3);
        pool.push(vec![1, 2, 3]);
        pool.push(vec![4, 5, 6]);
        pool.push(vec![7, 8, 9]);
        assert_eq!(pool.len(), 3);

        // Adding a 4th should evict the first
        pool.push(vec![10, 11, 12]);
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn test_pool_digest_changes_on_push() {
        let mut pool = EntropyPool::new(8);
        pool.push(vec![1, 2, 3]);
        let d1 = pool.digest();

        pool.push(vec![4, 5, 6]);
        let d2 = pool.digest();

        assert_ne!(d1, d2);
    }

    #[test]
    fn test_pool_same_data_same_digest() {
        let mut pool_a = EntropyPool::new(8);
        let mut pool_b = EntropyPool::new(8);

        pool_a.push(vec![42; 32]);
        pool_b.push(vec![42; 32]);

        assert_eq!(pool_a.digest(), pool_b.digest());
    }
}
