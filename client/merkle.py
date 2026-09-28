"""Builds Merkle trees and proofs exactly like contracts/Sha256Merkle.sol checks them. Pure hashlib, no chain."""  # Purpose.

import hashlib  # SHA-256, matching Solidity's sha256() precompile.
from typing import List, Tuple  # Type hints.

from client.config import MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX  # Same prefixes as the contract (rule M4).


def leaf_hash(doc_hash: bytes, subject_hash: bytes) -> bytes:  # Mirrors Sha256Merkle.leaf().
    """Return SHA-256(0x00 || docHash || subjectHash)."""  # Contract.
    return hashlib.sha256(MERKLE_LEAF_PREFIX + doc_hash + subject_hash).digest()  # Same byte layout as abi.encodePacked.


def node_hash(a: bytes, b: bytes) -> bytes:  # Mirrors Sha256Merkle._node().
    """Return SHA-256(0x01 || smaller || larger); byte-wise comparison equals Solidity's bytes32 `<`."""  # Contract.
    lo, hi = (a, b) if a < b else (b, a)  # Sort the pair so proofs need no left/right flags.
    return hashlib.sha256(MERKLE_NODE_PREFIX + lo + hi).digest()  # Hash prefix + children.


def _next_level(level: List[bytes]) -> List[bytes]:  # One step up the tree.
    """Return the parent level: pairs are hashed; an odd last node is carried up unchanged."""  # Contract.
    parents = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]  # Hash neighbours in pairs.
    if len(level) % 2 == 1:  # Odd count: the last node has no partner...
        parents.append(level[-1])  # ...so it moves up as-is (its proof simply skips this level).
    return parents  # Half the size (rounded up).


def build_tree(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:  # Used by the registrar when issuing a cohort.
    """Return (root, proofs) where proofs[i] lists the sibling hashes for leaves[i].

    Raises ValueError for an empty list or duplicate leaves (the same PDF+student twice).
    """  # Contract.
    if not leaves or len(set(leaves)) != len(leaves):  # Empty cohort or duplicates make no sense.
        raise ValueError("cohort must be non-empty with no duplicate members")  # Fail loudly.
    proofs = [[] for _ in leaves]  # One (initially empty) proof per leaf.
    positions = list(range(len(leaves)))  # Where each original leaf currently sits in the level.
    level = list(leaves)  # Start at the bottom.
    while len(level) > 1:  # Until only the root is left.
        for leaf_index, pos in enumerate(positions):  # Record each leaf's sibling at this level.
            sibling = pos + 1 if pos % 2 == 0 else pos - 1  # Partner is the neighbour in its pair.
            if sibling < len(level):  # No partner = carried up, nothing to record.
                proofs[leaf_index].append(level[sibling])  # Add the sibling hash to the proof.
        positions = [pos // 2 for pos in positions]  # Every node's position halves one level up.
        level = _next_level(level)  # Move up.
    return level[0], proofs  # The single remaining node is the root.


def verify_proof(proof: List[bytes], root: bytes, leaf: bytes) -> bool:  # Off-chain mirror of Sha256Merkle.verify().
    """Return True if hashing `leaf` up through `proof` reaches `root`."""  # Contract.
    computed = leaf  # Start at the bottom.
    for sibling in proof:  # Climb one level per sibling.
        computed = node_hash(computed, sibling)  # Parent hash.
    return computed == root  # Valid only if we land on the root.
