"""Business rules for issuing, verifying and revoking credentials. No web3 import (rule M3)."""  # Module purpose.

from pathlib import Path  # File path type for PDFs.
from typing import Optional, Protocol  # Protocol describes the chain interface without importing it.

from client import hashing  # Off-chain hashing helpers.
from client.models import IssueReceipt, OnChainRecord, Outcome, Status, VerificationResult  # Plain data types.


class ChainPort(Protocol):  # The shape of anything that can act as "the chain" (real adapter or a test fake).
    """Interface the domain needs from the chain layer; RegistryChain implements it, tests use a fake."""  # Why it exists.

    def issue(self, doc_hash: bytes, subject_hash: bytes, actor: str) -> str: ...  # Returns tx hash; raises RegistryError.

    def revoke(self, doc_hash: bytes, reason: bytes, actor: str) -> str: ...  # Returns tx hash; raises RegistryError.

    def get_record(self, doc_hash: bytes) -> OnChainRecord: ...  # Returns the record (status NONE if unknown).


_STATUS_TO_OUTCOME = {  # Translates contract states into verifier-facing answers.
    Status.VALID: Outcome.VALID,  # Issued and live.
    Status.REVOKED: Outcome.REVOKED,  # Issued then revoked - reported as such, not as missing.
    Status.NONE: Outcome.NOT_REGISTERED,  # Unknown hash: tampered or never issued.
}  # end of _STATUS_TO_OUTCOME


def issue_credential(chain: ChainPort, pdf: Path, student_id: str, actor: str) -> IssueReceipt:  # Registrar action.
    """Hash the PDF and a freshly salted student id, record both on-chain, and return the receipt.

    Takes the chain adapter, the PDF path, the student's id and the sending actor.
    Returns an IssueReceipt holding the secret salt. Raises RegistryError if the contract rejects it.
    """  # Multi-line docstring: inputs, output, failure.
    doc_hash = hashing.sha256_file(pdf)  # Fingerprint of the exact PDF bytes.
    salt = hashing.new_salt()  # Fresh random salt so this student's hash cannot be found from a roll list.
    subject = hashing.subject_hash(student_id, salt)  # Salted link to the student; the id itself never goes on-chain.
    tx_hash = chain.issue(doc_hash, subject, actor)  # Write to the chain (may raise RegistryError).
    return IssueReceipt(doc_hash, subject, salt, tx_hash)  # Everything the registrar must keep / hand to the student.


def verify_credential(  # Anyone's action; costs nothing because it is a read.
    chain: ChainPort, pdf: Path, student_id: Optional[str] = None, salt: Optional[bytes] = None
) -> VerificationResult:  # Signature split over lines for readability.
    """Re-hash the PDF and look it up. If student_id and salt are given, also check the credential is theirs.

    Returns a VerificationResult; never raises for a missing record (that is NOT_REGISTERED).
    """  # Docstring: inputs, output, behaviour on unknown documents.
    doc_hash = hashing.sha256_file(pdf)  # One changed byte gives a completely different hash.
    return result_from_record(doc_hash, chain.get_record(doc_hash), student_id, salt)  # Free read, then interpret.


def result_from_record(
    doc_hash: bytes, record: OnChainRecord, student_id: Optional[str], salt: Optional[bytes]
) -> VerificationResult:  # Shared by single-credential and cohort verification.
    """Turn an on-chain record into a VerificationResult, including the optional ownership check."""  # Contract.
    outcome = _STATUS_TO_OUTCOME[record.status]  # Map contract state to a human answer.
    if outcome is Outcome.NOT_REGISTERED:  # Nothing on-chain for this file.
        return VerificationResult(outcome, doc_hash, None, None)  # No record, nothing to compare.
    match = _subject_matches(record, student_id, salt)  # Optional ownership check.
    return VerificationResult(outcome, doc_hash, record, match)  # Full evidence for the caller.


def revoke_credential(chain: ChainPort, pdf: Path, reason: str, actor: str) -> str:  # Registrar action.
    """Revoke the credential for this PDF, storing only a hash of the reason. Returns the tx hash.

    Raises RegistryError if the contract rejects it (not issued, already revoked, wrong issuer, no role).
    """  # Docstring.
    doc_hash = hashing.sha256_file(pdf)  # Identify the credential by the PDF's hash.
    return chain.revoke(doc_hash, hashing.reason_code(reason), actor)  # Reason text stays off-chain.


def _subject_matches(record: OnChainRecord, student_id: Optional[str], salt: Optional[bytes]) -> Optional[bool]:  # Helper.
    """Return None if no id/salt supplied, else whether SHA-256(salt || id) equals the on-chain subject hash."""  # Contract.
    if student_id is None or salt is None:  # Ownership check is optional.
        return None  # "Not checked" is different from "does not match".
    return hashing.subject_hash(student_id, salt) == record.subject_hash  # Recompute and compare.
