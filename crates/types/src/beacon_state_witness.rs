//! The top-level SSZ leaves of a `BeaconState`. EIP-8440 anchors an execution proof to the beacon
//! chain, so its guest reads fields of the state of the beacon block that carries the payload.

use alloy_primitives::B256;
use libssz_derive::{SszDecode, SszEncode};
use sha2::{Digest, Sha256};
use stateless_validator_common::SszList;

/// Upper bound of the top-level field count of a `BeaconState`. The leaves merkleize over the
/// field count rounded up to a power of two, so a fork with more fields needs a larger bound.
pub const MAX_BEACON_STATE_LEAVES: usize = 64;

/// The hash tree root of every top-level field of a `BeaconState`, in field order.
///
/// The leaves merkleize to the state root, so they witness every top-level field without a merkle
/// branch per field: a reader of a field supplies the value and compares its hash tree root with
/// the leaf at the index of the field. An unread field costs its 32-byte leaf, so the witness of a
/// mainnet state is about a kilobyte in place of its hundreds of megabytes.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BeaconStateWitness {
    /// Hash tree root of every top-level field of the state, in field order.
    pub leaves: SszList<[u8; 32], MAX_BEACON_STATE_LEAVES>,
}

impl BeaconStateWitness {
    /// Collects the top-level leaves of a state into a witness.
    pub fn new(leaves: Vec<[u8; 32]>) -> anyhow::Result<Self> {
        Ok(Self {
            leaves: SszList::try_from(leaves).map_err(|error| {
                anyhow::anyhow!("beacon state leaf count out of bounds: {error:?}")
            })?,
        })
    }

    /// Merkleizes the leaves into the state root. They pad to the next power of two with zero
    /// chunks, as the SSZ merkleization of a container does.
    pub fn state_root(&self) -> B256 {
        let mut nodes = self.leaves.to_vec();
        nodes.resize(nodes.len().next_power_of_two(), [0; 32]);
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    Sha256::new()
                        .chain_update(pair[0])
                        .chain_update(pair[1])
                        .finalize()
                        .into()
                })
                .collect();
        }
        B256::from(nodes[0])
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use lighthouse_types::{BeaconState, ChainSpec, Eth1Data, MainnetEthSpec};
    use sha2::{Digest, Sha256};

    use crate::{BeaconStateWitness, SszDecode, SszEncode};

    /// Hashes a pair of nodes as the merkleization does.
    fn hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        Sha256::new()
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }

    /// Three leaves pad to four, so the root is the tree over the leaves and one zero chunk.
    #[test]
    fn test_state_root_pads_to_a_power_of_two() {
        let witness = BeaconStateWitness::new(vec![[1; 32], [2; 32], [3; 32]]).unwrap();
        assert_eq!(
            witness.state_root(),
            B256::from(hash(hash([1; 32], [2; 32]), hash([3; 32], [0; 32])))
        );
    }

    /// The leaves of a state merkleize to the state root that lighthouse computes over the whole
    /// state. This is what lets the leaves stand in for the state.
    #[test]
    fn test_state_leaves_merkleize_to_the_state_root() {
        let spec = ChainSpec::mainnet();
        let mut state = BeaconState::<MainnetEthSpec>::new(0, Eth1Data::default(), &spec);
        let leaves = state
            .get_beacon_state_leaves()
            .into_iter()
            .map(|leaf| leaf.0)
            .collect();

        let witness = BeaconStateWitness::new(leaves).unwrap();
        assert_eq!(witness.state_root(), state.canonical_root().unwrap());
    }

    /// The witness round-trips through SSZ, as it travels to the guest.
    #[test]
    fn test_witness_ssz_round_trip() {
        let witness = BeaconStateWitness::new(vec![[7; 32], [8; 32]]).unwrap();
        let encoded = witness.to_ssz();
        assert_eq!(
            BeaconStateWitness::from_ssz_bytes(&encoded).unwrap(),
            witness
        );
    }
}
