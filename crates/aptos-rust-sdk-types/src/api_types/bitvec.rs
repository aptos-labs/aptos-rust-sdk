// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

//! This module defines a BitVec struct that represents a bit vector.
//! Based on the official Aptos implementation.

use serde::{de::Error, Deserialize, Deserializer, Serialize};
use std::ops::{BitAnd, BitOr};

/// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;
const MAX_BUCKETS: usize = 8192;

/// BitVec represents a bit vector that supports 4 operations:
///
/// 1. Marking a position as set.
/// 2. Checking if a position is set.
/// 3. Count set bits.
/// 4. Get the index of the last set bit.
///
/// Internally, it stores a vector of u8's (as `Vec<u8>`).
///
/// * The first 8 positions of the bit vector are encoded in the first element of the vector, the
///   next 8 are encoded in the second element, and so on.
/// * Bits are read from left to right. For instance, in the following bitvec
///   [0b0001_0000, 0b0000_0000, 0b0000_0000, 0b0000_0001], the 3rd and 31st positions are set.
/// * Each bit of a u8 is set to 1 if the position is set and to 0 if it's not.
/// * We only allow setting positions upto u16::MAX. As a result, the size of the inner vector is
///   limited to 8192 (= 65536 / 8).
/// * Once a bit has been set, it cannot be unset. As a result, the inner vector cannot shrink.
/// * The positions can be set in any order.
/// * A position can set more than once -- it remains set after the first time.
#[derive(Clone, Default, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct BitVec {
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl BitVec {
    /// Create a new BitVec with specified capacity.
    fn with_capacity(num_buckets: usize) -> Self {
        Self {
            inner: Vec::with_capacity(num_buckets),
        }
    }

    /// Initialize with buckets that can fit in num_bits.
    pub fn with_num_bits(num_bits: u16) -> Self {
        Self {
            inner: vec![0; Self::required_buckets(num_bits)],
        }
    }

    /// Sets the bit at position @pos.
    pub fn set(&mut self, pos: u16) {
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            self.inner.resize(bucket + 1, 0);
        }
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        self.inner[bucket] |= 0b1000_0000 >> bucket_pos as u8;
    }

    /// Checks if the bit at position @pos is set.
    #[inline]
    pub fn is_set(&self, pos: u16) -> bool {
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            return false;
        }
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        (self.inner[bucket] & (0b1000_0000 >> bucket_pos as u8)) != 0
    }

    /// Return true if the BitVec is all zeros.
    pub fn all_zeros(&self) -> bool {
        self.inner.iter().all(|byte| *byte == 0)
    }

    /// Returns the number of set bits.
    pub fn count_ones(&self) -> u32 {
        self.inner.iter().map(|a| a.count_ones()).sum()
    }

    /// Returns the index of the last set bit.
    pub fn last_set_bit(&self) -> Option<u16> {
        self.inner
            .iter()
            .rev()
            .enumerate()
            .find(|(_, byte)| byte != &&0u8)
            .map(|(i, byte)| {
                (8 * (self.inner.len() - i) - byte.trailing_zeros() as usize - 1) as u16
            })
    }

    /// Return an `Iterator` over all '1' bit indexes.
    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.inner.len() * BUCKET_SIZE).filter(move |idx| self.is_set(*idx as u16))
    }

    /// Return the number of buckets.
    pub fn num_buckets(&self) -> usize {
        self.inner.len()
    }

    /// Number of buckets required for num_bits.
    pub fn required_buckets(num_bits: u16) -> usize {
        num_bits
            .checked_sub(1)
            .map_or(0, |pos| pos as usize / BUCKET_SIZE + 1)
    }
}

impl BitAnd for &BitVec {
    type Output = BitVec;

    /// Returns a new BitVec that is a bitwise AND of two BitVecs.
    fn bitand(self, other: Self) -> Self::Output {
        let len = std::cmp::min(self.inner.len(), other.inner.len());
        let mut ret = BitVec::with_capacity(len);
        for i in 0..len {
            ret.inner.push(self.inner[i] & other.inner[i]);
        }
        ret
    }
}

impl BitOr for &BitVec {
    type Output = BitVec;

    /// Returns a new BitVec that is a bitwise OR of two BitVecs.
    fn bitor(self, other: Self) -> Self::Output {
        let len = std::cmp::max(self.inner.len(), other.inner.len());
        let mut ret = BitVec::with_capacity(len);
        for i in 0..len {
            let a = self.inner.get(i).copied().unwrap_or(0);
            let b = other.inner.get(i).copied().unwrap_or(0);
            ret.inner.push(a | b);
        }
        ret
    }
}

impl FromIterator<u8> for BitVec {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        let mut bitvec = Self::default();
        for bit in iter {
            bitvec.set(bit as u16);
        }
        bitvec
    }
}

impl From<Vec<u8>> for BitVec {
    fn from(raw_bytes: Vec<u8>) -> Self {
        assert!(raw_bytes.len() <= MAX_BUCKETS);
        Self { inner: raw_bytes }
    }
}

impl From<BitVec> for Vec<u8> {
    fn from(bitvec: BitVec) -> Self {
        bitvec.inner
    }
}

impl From<Vec<bool>> for BitVec {
    fn from(bits: Vec<bool>) -> Self {
        BitVec::from(&bits)
    }
}

impl From<&Vec<bool>> for BitVec {
    fn from(bits: &Vec<bool>) -> Self {
        assert!(bits.len() <= MAX_BUCKETS * BUCKET_SIZE);
        let mut bitvec = Self::with_num_bits(bits.len() as u16);
        for (index, b) in bits.iter().enumerate() {
            if *b {
                bitvec.set(index as u16);
            }
        }
        bitvec
    }
}

impl FromIterator<bool> for BitVec {
    fn from_iter<T: IntoIterator<Item = bool>>(iter: T) -> Self {
        let mut bitvec = Self::default();
        for (index, bit) in iter.into_iter().enumerate() {
            if bit {
                bitvec.set(index as u16);
            }
        }
        bitvec
    }
}

impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "BitVec")]
        struct RawData {
            #[serde(with = "serde_bytes")]
            inner: Vec<u8>,
        }
        let v = RawData::deserialize(deserializer)?.inner;
        if v.len() > MAX_BUCKETS {
            return Err(D::Error::custom(format!("BitVec too long: {}", v.len())));
        }
        Ok(BitVec { inner: v })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_ones() {
        let p0 = BitVec::default();
        assert_eq!(p0.count_ones(), 0);

        // 7 = b'0000111' and 15 = b'00001111'
        let p1 = BitVec {
            inner: vec![7u8, 15u8],
        };
        assert_eq!(p1.count_ones(), 7);
    }

    #[test]
    fn test_last_set_bit() {
        let p0 = BitVec::default();
        assert_eq!(p0.last_set_bit(), None);

        // 224 = b'11100000'
        let p1 = BitVec { inner: vec![224u8] };
        assert_eq!(p1.last_set_bit(), Some(2));

        // 128 = 0b1000_0000
        let p2 = BitVec {
            inner: vec![7u8, 128u8],
        };
        assert_eq!(p2.last_set_bit(), Some(8));
    }

    #[test]
    fn test_set_and_is_set() {
        let mut bv = BitVec::default();
        bv.set(2);
        bv.set(5);
        assert!(bv.is_set(2));
        assert!(bv.is_set(5));
        assert!(!bv.is_set(0));
        assert!(!bv.is_set(1));
        assert_eq!(bv.count_ones(), 2);
    }

    #[test]
    fn test_iter_ones() {
        let mut bv = BitVec::default();
        bv.set(0);
        bv.set(3);
        bv.set(7);
        let ones: Vec<usize> = bv.iter_ones().collect();
        assert_eq!(ones, vec![0, 3, 7]);
    }

    #[test]
    fn test_bitwise_and() {
        let mut bv1 = BitVec::default();
        bv1.set(2);
        bv1.set(3);
        let mut bv2 = BitVec::default();
        bv2.set(2);
        let intersection = (&bv1).bitand(&bv2);
        assert!(intersection.is_set(2));
        assert!(!intersection.is_set(3));
    }

    #[test]
    fn test_from_vec_bool() {
        let bitmaps = vec![false, true, true, false, false, true, true, false, true];
        let bitvec = BitVec::from(bitmaps.clone());
        for (index, is_set) in bitmaps.into_iter().enumerate() {
            assert_eq!(bitvec.is_set(index as u16), is_set);
        }
    }
}
