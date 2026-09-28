// SPDX-License-Identifier: MIT
// ^ Licence tag required by the compiler.
pragma solidity 0.8.24; // Same pinned compiler as the registry.

/// @title Sha256Merkle
/// @notice Checks that a leaf belongs to a Merkle tree, using SHA-256 so the Python client needs only hashlib.
/// @dev Pairs are sorted before hashing, so a proof is just a list of sibling hashes (no left/right flags).
///      Leaves and inner nodes get different one-byte prefixes, so an inner node can never be passed off as a leaf.
library Sha256Merkle { // A library: pure helper code linked into the registry, holds no storage.
    bytes1 internal constant LEAF_PREFIX = 0x00; // Domain-separation byte for leaves.
    bytes1 internal constant NODE_PREFIX = 0x01; // Domain-separation byte for inner nodes.
    uint256 internal constant MAX_PROOF_DEPTH = 32; // 2^32 leaves is far beyond any cohort; caps the loop below.

    /// @notice Hash of one cohort member: SHA-256(0x00 || docHash || subjectHash).
    /// @param docHash SHA-256 of the member's PDF.
    /// @param subjectHash Salted student-id hash of the member.
    /// @return The leaf hash that sits at the bottom of the tree.
    function leaf(bytes32 docHash, bytes32 subjectHash) internal pure returns (bytes32) { // `pure` = reads no state.
        return sha256(abi.encodePacked(LEAF_PREFIX, docHash, subjectHash)); // Tightly packed 65 bytes -> SHA-256 precompile.
    } // end of leaf

    /// @notice Returns true if `leafHash` with the sibling hashes in `proof` rebuilds `root`.
    /// @param proof Sibling hashes from the leaf level up to just below the root.
    /// @param root Merkle root that was stored on-chain for the cohort.
    /// @param leafHash Output of leaf() for the member being checked.
    /// @return True if the proof is valid; false (never reverts) if it is not or is too long.
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leafHash) internal pure returns (bool) { // Core check.
        if (proof.length > MAX_PROOF_DEPTH) return false; // Refuse absurd proofs so the loop is bounded.
        bytes32 computed = leafHash; // Start at the bottom of the tree.
        for (uint256 i = 0; i < proof.length; i++) { // Climb one level per sibling.
            computed = _node(computed, proof[i]); // Combine with the sibling to get the parent.
        } // end of for
        return computed == root; // Valid only if we arrive exactly at the stored root.
    } // end of verify

    /// @dev Parent of two nodes: SHA-256(0x01 || smaller || larger). Sorting makes order irrelevant.
    function _node(bytes32 a, bytes32 b) private pure returns (bytes32) { // Private helper.
        (bytes32 lo, bytes32 hi) = a < b ? (a, b) : (b, a); // Put the smaller value first.
        return sha256(abi.encodePacked(NODE_PREFIX, lo, hi)); // Hash prefix + both children.
    } // end of _node
} // end of library Sha256Merkle
