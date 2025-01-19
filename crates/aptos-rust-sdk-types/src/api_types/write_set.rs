use std::collections::{btree_map, BTreeMap};
use serde::{Deserialize, Serialize};
use crate::api_types::state_key::StateKey;

#[derive(
Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize,
)]
pub enum WriteSet {
    V0(WriteSetV0),
}


/// `WriteSet` contains all access paths that one transaction modifies. Each of them is a `WriteOp`
/// where `Value(val)` means that serialized representation should be updated to `val`, and
/// `Deletion` means that we are going to delete this access path.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize,
)]
pub struct WriteSetV0(WriteSetMut);

impl WriteSetV0 {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> btree_map::Iter<'_, StateKey, WriteOp> {
        self.0.write_set.iter()
    }

    pub fn get(&self, key: &StateKey) -> Option<&WriteOp> {
        self.0.get(key)
    }
}

/// A mutable version of `WriteSet`.
///
/// This is separate because it goes through validation before becoming an immutable `WriteSet`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct WriteSetMut {
    // TODO: Change to HashMap with a stable iterator for serialization.
    write_set: BTreeMap<StateKey, WriteOp>,
}

impl WriteSetMut {
    pub fn new(write_ops: impl IntoIterator<Item=(StateKey, WriteOp)>) -> Self {
        Self {
            write_set: write_ops.into_iter().collect(),
        }
    }

    pub fn insert(&mut self, item: (StateKey, WriteOp)) {
        self.write_set.insert(item.0, item.1);
    }

    pub fn extend(&mut self, write_ops: impl IntoIterator<Item=(StateKey, WriteOp)>) {
        self.write_set.extend(write_ops);
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.write_set.is_empty()
    }

    pub fn len(&self) -> usize {
        self.write_set.len()
    }

    pub fn freeze(self) -> anyhow::Result<WriteSet> {
        // TODO: add structural validation
        Ok(WriteSet::V0(WriteSetV0(self)))
    }

    pub fn get(&self, key: &StateKey) -> Option<&WriteOp> {
        self.write_set.get(key)
    }

    pub fn as_inner_mut(&mut self) -> &mut BTreeMap<StateKey, WriteOp> {
        &mut self.write_set
    }

    pub fn squash(mut self, other: Self) -> anyhow::Result<Self> {
        use btree_map::Entry::*;

        for (key, op) in other.write_set.into_iter() {
            match self.write_set.entry(key) {
                Occupied(_entry) => {
                    /*TODO: FIXME if !WriteOp::squash(entry.get_mut(), op)? {
                        entry.remove();
                    }*/
                }
                Vacant(entry) => {
                    entry.insert(op);
                }
            }
        }

        Ok(self)
    }
}


#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum WriteOp {
    Creation {
        data: Vec<u8>,
        metadata: StateValueMetadata,
    },
    Modification {
        data: Vec<u8>,
        metadata: StateValueMetadata,
    },
    Deletion {
        metadata: StateValueMetadata,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct StateValueMetadata {
    inner: Option<StateValueMetadataInner>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct StateValueMetadataInner {
    slot_deposit: u64,
    bytes_deposit: u64,
    creation_time_usecs: u64,
}