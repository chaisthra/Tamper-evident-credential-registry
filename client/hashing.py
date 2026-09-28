"""Off-chain hashing: PDF fingerprints, salted student-id hashes, and reason codes. Pure Python, no chain access."""  # Module purpose.

import hashlib  # Standard-library SHA-256.
import secrets  # Cryptographically secure randomness for salts (unlike `random`).
from pathlib import Path  # File path type.

from client.config import HASH_BYTES, READ_CHUNK_BYTES, SALT_BYTES  # Named constants (rule M4).


def sha256_file(path: Path) -> bytes:  # Fingerprint of a document.
    """Return the 32-byte SHA-256 of the file's exact bytes. Raises FileNotFoundError if the path is missing."""  # Contract of the function.
    digest = hashlib.sha256()  # Start an incremental hash.
    with open(path, "rb") as handle:  # Binary mode: hash bytes exactly as stored, no newline translation.
        for chunk in iter(lambda: handle.read(READ_CHUNK_BYTES), b""):  # Read piece by piece until EOF (b"").
            digest.update(chunk)  # Feed each piece into the hash.
    return digest.digest()  # 32 raw bytes, ready to use as Solidity bytes32.


def new_salt() -> bytes:  # One fresh salt per student credential.
    """Return SALT_BYTES of secure random data."""  # Contract of the function.
    return secrets.token_bytes(SALT_BYTES)  # OS randomness; unpredictable, so the subject hash cannot be guessed.


def normalise_student_id(student_id: str) -> str:  # "cs2024001 " and "CS2024001" must hash the same.
    """Return the id stripped of spaces and upper-cased. Raises ValueError if it is empty."""  # Contract.
    cleaned = student_id.strip().upper()  # Remove surrounding whitespace, fix case.
    if not cleaned:  # An empty id would make every empty-id hash identical.
        raise ValueError("student id must not be empty")  # Fail loudly.
    return cleaned  # Canonical form.


def subject_hash(student_id: str, salt: bytes) -> bytes:  # The on-chain link to a student, without revealing them.
    """Return SHA-256(salt || normalised id). Raises ValueError if the salt is not SALT_BYTES long."""  # Contract.
    if len(salt) != SALT_BYTES:  # A short or missing salt would make the hash brute-forceable from a roll list.
        raise ValueError(f"salt must be {SALT_BYTES} bytes")  # Refuse weak input.
    return hashlib.sha256(salt + normalise_student_id(student_id).encode("utf-8")).digest()  # Salt first, then id bytes.


def reason_code(reason: str) -> bytes:  # The revocation reason stays off-chain; only its hash goes on-chain.
    """Return SHA-256 of the reason text, so the reason is private but can later be proven."""  # Contract.
    return hashlib.sha256(reason.encode("utf-8")).digest()  # 32 bytes for Solidity bytes32.


def to_hex(value: bytes) -> str:  # Display helper.
    """Return the bytes as a 0x-prefixed hex string."""  # Contract.
    return "0x" + value.hex()  # Standard Ethereum hex notation.


def from_hex(text: str) -> bytes:  # Parses user input like a salt typed on the command line.
    """Return bytes from a hex string with or without 0x. Raises ValueError on bad hex."""  # Contract.
    return bytes.fromhex(text[2:] if text.startswith("0x") else text)  # Strip optional prefix, then decode.


def is_hash_sized(value: bytes) -> bool:  # Sanity check before sending to the chain.
    """Return True if value is exactly HASH_BYTES long (fits Solidity bytes32)."""  # Contract.
    return len(value) == HASH_BYTES  # bytes32 needs exactly 32 bytes.
