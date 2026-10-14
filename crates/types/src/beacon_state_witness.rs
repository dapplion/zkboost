//! The top-level SSZ leaves of a post-Gloas `BeaconState`. EIP-8440 anchors an execution proof to
//! the beacon chain, so its guest reads fields of the state of the beacon block that carries the
//! payload. Only Gloas onwards has the payload bid that binds the two, so earlier states have no
//! witness.

use alloy_primitives::B256;
use anyhow::ensure;
use libssz_derive::{SszDecode, SszEncode};
use libssz_merkle::{merkleize_progressive, mix_in_active_fields};
use stateless_validator_common::{Sha2Hasher, SszList};

/// Active field count of the Gloas `BeaconState`, which fixes the shape of its progressive
/// merkleization. A fork that appends a field needs a larger count.
pub const STATE_FIELD_COUNT: usize = 46;

/// The hash tree root of every top-level field of a `BeaconState`, in field order.
///
/// The leaves merkleize to the state root, so they witness every top-level field without a merkle
/// branch per field: a reader of a field supplies the value and compares its hash tree root with
/// the leaf at the index of the field. An unread field costs its 32-byte leaf, so the witness of a
/// mainnet state is under one and a half kilobytes in place of its hundreds of megabytes.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BeaconStateWitness {
    /// Hash tree root of every top-level field of the state, in field order.
    pub leaves: SszList<[u8; 32], STATE_FIELD_COUNT>,
}

impl BeaconStateWitness {
    /// Collects the top-level leaves of a state into a witness. A state of another fork has
    /// another field count, which the leaves must carry for the merkleization to reach its root.
    pub fn new(leaves: Vec<[u8; 32]>) -> anyhow::Result<Self> {
        ensure!(
            leaves.len() == STATE_FIELD_COUNT,
            "beacon state has {} top-level fields, not the {STATE_FIELD_COUNT} of Gloas",
            leaves.len()
        );
        Ok(Self {
            leaves: SszList::try_from(leaves).map_err(|error| {
                anyhow::anyhow!("beacon state leaf count out of bounds: {error:?}")
            })?,
        })
    }

    /// Merkleizes the leaves into the state root. A post-Gloas `BeaconState` is a
    /// `ProgressiveContainer`, so its field roots form a zero-terminated spine of binary subtrees
    /// of 1, 4, 16, 64, ... leaves with the active field bits mixed in, not one balanced tree.
    pub fn state_root(&self) -> B256 {
        B256::from(mix_in_active_fields(
            &Sha2Hasher,
            &merkleize_progressive(&Sha2Hasher, &self.leaves),
            &[true; STATE_FIELD_COUNT],
        ))
    }
}

#[cfg(test)]
mod tests {
    use libssz_merkle::{Sha2Hasher, hash_nodes, merkleize};

    use crate::{BeaconStateWitness, STATE_FIELD_COUNT, SszDecode, SszEncode};

    /// The leaves of a state, as distinct values in field order.
    fn leaves() -> Vec<[u8; 32]> {
        (0..STATE_FIELD_COUNT as u8)
            .map(|field| [field; 32])
            .collect()
    }

    /// The root is the progressive spine of EIP-7916 spelled out: binary subtrees of 1, 4, 16 and
    /// 64 leaves, the last holding the 25 remaining fields, terminated by a zero node, with the 46
    /// active field bits mixed in.
    #[test]
    fn test_state_root_is_the_progressive_spine() {
        let leaves = leaves();
        let subtree = |range: core::ops::Range<usize>, limit: usize| {
            merkleize(&Sha2Hasher, &leaves[range], Some(limit))
        };
        let spine = hash_nodes(
            &Sha2Hasher,
            &subtree(0..1, 1),
            &hash_nodes(
                &Sha2Hasher,
                &subtree(1..5, 4),
                &hash_nodes(
                    &Sha2Hasher,
                    &subtree(5..21, 16),
                    &hash_nodes(&Sha2Hasher, &subtree(21..46, 64), &[0; 32]),
                ),
            ),
        );
        let mut active_fields = [0u8; 32];
        for field in 0..STATE_FIELD_COUNT {
            active_fields[field / 8] |= 1 << (field % 8);
        }

        assert_eq!(
            BeaconStateWitness::new(leaves).unwrap().state_root().0,
            hash_nodes(&Sha2Hasher, &spine, &active_fields)
        );
    }

    /// A state of another fork has another field count, which the witness rejects rather than
    /// merkleize into a root that no beacon block carries.
    #[test]
    fn test_witness_rejects_another_field_count() {
        assert!(BeaconStateWitness::new(leaves()[..45].to_vec()).is_err());
    }

    /// The witness round-trips through SSZ, as it travels to the guest.
    #[test]
    fn test_witness_ssz_round_trip() {
        let witness = BeaconStateWitness::new(leaves()).unwrap();
        let encoded = witness.to_ssz();
        assert_eq!(
            BeaconStateWitness::from_ssz_bytes(&encoded).unwrap(),
            witness
        );
    }
}
