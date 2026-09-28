"""Plain data types shared by the chain adapter and the domain logic (no web3 here)."""  # Keeps layers decoupled (rule M3).

from dataclasses import dataclass  # Generates __init__/__eq__ for simple record classes.
from enum import Enum, IntEnum  # Enum for named outcomes; IntEnum for values that come back from the chain as ints.
from typing import Optional  # Marks fields that may be None.


class Status(IntEnum):  # Mirrors the Solidity `Status` enum; IntEnum so Status(1) works on raw chain output.
    """On-chain life-cycle state of a credential. Order must match the contract."""  # Why the numbers matter.

    NONE = 0  # Never issued (or tampered: the hash is unknown).
    VALID = 1  # Issued and not revoked.
    REVOKED = 2  # Issued, then revoked.


class Outcome(Enum):  # What a verifier is told; distinct from Status because NONE means "not registered" to a human.
    """Result of verifying a PDF, in the words shown to the user."""  # Human-facing meaning.

    VALID = "VALID"  # The exact file was issued and is still valid.
    REVOKED = "REVOKED"  # The exact file was issued but has been revoked.
    NOT_REGISTERED = "NOT_REGISTERED"  # No record: the file was altered or never issued (the chain cannot tell which).


class RegistryError(Exception):  # Raised by the chain adapter when a transaction reverts.
    """A transaction was rejected by the contract; `reason` is the Solidity custom error name."""  # For readable CLI output.

    def __init__(self, reason: str) -> None:  # Takes the decoded error name, e.g. "AlreadyIssued".
        super().__init__(reason)  # Keeps the normal Exception message behaviour.
        self.reason = reason  # Stored separately so callers can branch on it.


@dataclass(frozen=True)  # frozen = immutable, so a record read from the chain cannot be edited by mistake.
class OnChainRecord:  # Python view of the Solidity `Credential` struct.
    """One credential as stored on-chain."""  # Docstring for the class.

    subject_hash: bytes  # SHA-256(salt || studentId).
    issuer: str  # Address of the issuing registrar.
    issued_at: int  # Unix time of issue (0 if never issued).
    revoked_at: int  # Unix time of revocation (0 if not revoked).
    status: Status  # NONE / VALID / REVOKED.


@dataclass(frozen=True)  # Immutable result object.
class IssueReceipt:  # What the registrar keeps (and gives the student) after issuing.
    """Output of issuing: the hashes that went on-chain, the secret salt, and the transaction id."""  # Purpose.

    doc_hash: bytes  # SHA-256 of the PDF.
    subject_hash: bytes  # Salted student-id hash that went on-chain.
    salt: bytes  # Secret salt - off-chain only; the student needs it to prove the credential is theirs.
    tx_hash: str  # Transaction hash, for the audit trail.


@dataclass(frozen=True)  # Immutable result object.
class VerificationResult:  # What `verify` returns to the CLI.
    """Outcome of checking a PDF, plus the evidence behind it."""  # Purpose.

    outcome: Outcome  # VALID / REVOKED / NOT_REGISTERED.
    doc_hash: bytes  # Hash of the file that was checked.
    record: Optional[OnChainRecord]  # The on-chain record, or None if not registered.
    subject_match: Optional[bool]  # True/False if a student id + salt were supplied, else None.
