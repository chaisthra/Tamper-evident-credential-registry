"""Stretch goal: issue a whole cohort under one Merkle root, and verify/revoke single members. No web3 import."""  # Purpose.

from dataclasses import dataclass  # Simple immutable record.
from pathlib import Path  # File paths.
from typing import List, Optional, Protocol, Tuple  # Type hints.

from client import hashing, merkle  # Off-chain hashing and Merkle helpers.
from client.domain import result_from_record  # Same result logic as single credentials.
from client.models import BatchMember, OnChainRecord, VerificationResult  # Plain data types.


class CohortChainPort(Protocol):  # What this module needs from the chain layer (RegistryChain or a test fake).
    """Chain interface for cohort operations."""  # Why it exists.

    def issue_batch(self, root: bytes, size: int, actor: str) -> str: ...  # Returns tx hash.

    def revoke_batch_member(self, member: BatchMember, reason: bytes, actor: str) -> str: ...  # Returns tx hash.

    def get_batch_record(self, member: BatchMember) -> OnChainRecord: ...  # Returns record (NONE if not a member).


@dataclass(frozen=True)  # Immutable.
class CohortReceipt:  # What the registrar gets back after issuing a cohort.
    """The cohort root, the issuing transaction, and one proof bundle per student (keyed by student id)."""  # Purpose.

    root: bytes  # Merkle root now stored on-chain.
    tx_hash: str  # Issuing transaction.
    bundles: dict  # student id -> bundle dict (hex strings, ready to save as JSON and hand to the student).


def issue_cohort(chain: CohortChainPort, members: List[Tuple[Path, str]], actor: str) -> CohortReceipt:  # Registrar action.
    """Hash every (pdf, student id), build the Merkle tree, store only the root on-chain, return per-student bundles.

    Raises ValueError for an empty cohort or duplicates, RegistryError if the contract rejects it.
    """  # Contract.
    salts = [hashing.new_salt() for _ in members]  # A fresh secret salt per student.
    subjects = [hashing.subject_hash(sid, salt) for (_, sid), salt in zip(members, salts)]  # Salted id hashes.
    leaves = [merkle.leaf_hash(hashing.sha256_file(pdf), subj) for (pdf, _), subj in zip(members, subjects)]  # One leaf each.
    root, proofs = merkle.build_tree(leaves)  # Root + a proof for every leaf.
    tx_hash = chain.issue_batch(root, len(leaves), actor)  # ONE transaction for the whole cohort.
    bundles = {  # Build each student's private proof bundle.
        sid: _bundle(root, subj, salt, proof)  # Everything needed to prove membership later.
        for (_, sid), subj, salt, proof in zip(members, subjects, salts, proofs)  # Walk the lists together.
    }  # end of bundles
    return CohortReceipt(root, tx_hash, bundles)  # Hand back to the CLI.


def verify_member(  # Anyone's action, free.
    chain: CohortChainPort, pdf: Path, bundle: dict, student_id: Optional[str] = None
) -> VerificationResult:  # Signature split for readability.
    """Re-hash the PDF and check it against the cohort root using the bundle's proof; optional ownership check."""  # Contract.
    member = to_member(pdf, bundle)  # Doc hash comes from the PDF actually presented, never from the bundle.
    salt = hashing.from_hex(bundle["salt"])  # The bundle carries the student's salt for the ownership check.
    return result_from_record(member.doc_hash, chain.get_batch_record(member), student_id, salt)  # Same logic as single.


def revoke_member(chain: CohortChainPort, pdf: Path, bundle: dict, reason: str, actor: str) -> str:  # Registrar action.
    """Revoke one cohort member; the others stay valid. Returns the tx hash; raises RegistryError on rejection."""  # Contract.
    return chain.revoke_batch_member(to_member(pdf, bundle), hashing.reason_code(reason), actor)  # Reason hash only.


def to_member(pdf: Path, bundle: dict) -> BatchMember:  # Converts a JSON bundle + PDF into chain arguments.
    """Return a BatchMember built from the PDF's real hash and the bundle's root, subject hash and proof."""  # Contract.
    return BatchMember(  # Build the record...
        root=hashing.from_hex(bundle["root"]),  # Cohort root.
        doc_hash=hashing.sha256_file(pdf),  # Recomputed: a tampered PDF gives a leaf that is not in the tree.
        subject_hash=hashing.from_hex(bundle["subject_hash"]),  # Salted id hash.
        proof=[hashing.from_hex(p) for p in bundle["proof"]],  # Sibling hashes.
    )  # end of BatchMember


def _bundle(root: bytes, subject: bytes, salt: bytes, proof: List[bytes]) -> dict:  # JSON-friendly bundle.
    """Return the student's proof bundle as hex strings. Contains the salt, so the student keeps it private."""  # Contract.
    return {  # Plain dict so it can be written with json.dump.
        "root": hashing.to_hex(root),  # Which cohort.
        "subject_hash": hashing.to_hex(subject),  # Salted id hash in the leaf.
        "salt": hashing.to_hex(salt),  # Secret; lets the student prove the credential is theirs.
        "proof": [hashing.to_hex(p) for p in proof],  # Path to the root.
    }  # end of bundle dict
