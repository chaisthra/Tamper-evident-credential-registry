"""In-memory stand-in for the chain, so domain tests run with no node and are fully deterministic."""  # Purpose.

from client import merkle  # Same proof check the contract performs.
from client.models import OnChainRecord, RegistryError, Status  # Same plain types the real adapter returns.

EMPTY = OnChainRecord(b"\x00" * 32, "0x" + "00" * 20, 0, 0, Status.NONE)  # What the contract returns for an unknown hash.
FAKE_TIME = 1_700_000_000  # Fixed "block timestamp" so results never depend on the clock.
REGISTRARS = {"registrar"}  # Actors that hold REGISTRAR_ROLE in this fake.


class FakeChain:  # Implements the domain's ChainPort interface with a dict.
    """Mimics CredentialRegistry's rules (role check, no double issue, revoke only if valid)."""  # What it models.

    def __init__(self) -> None:  # Starts empty.
        """Create an empty registry."""  # Contract.
        self.records = {}  # doc_hash -> OnChainRecord.
        self.batches = {}  # Merkle root -> issuer actor.
        self.revoked_leaves = set()  # (root, leaf) pairs that were revoked.

    def issue(self, doc_hash: bytes, subject_hash: bytes, actor: str) -> str:  # Same signature as RegistryChain.issue.
        """Store a VALID record; raise RegistryError like the contract would."""  # Contract.
        if actor not in REGISTRARS:  # Role check.
            raise RegistryError("AccessControlUnauthorizedAccount")  # Same name the real contract uses.
        if doc_hash in self.records:  # Duplicate check.
            raise RegistryError("AlreadyIssued")  # Same name as the contract error.
        self.records[doc_hash] = OnChainRecord(subject_hash, actor, FAKE_TIME, 0, Status.VALID)  # Store.
        return "0xfake"  # Placeholder tx hash.

    def revoke(self, doc_hash: bytes, reason: bytes, actor: str) -> str:  # Same signature as RegistryChain.revoke.
        """Mark a VALID record REVOKED; raise RegistryError otherwise."""  # Contract.
        if actor not in REGISTRARS:  # Role check.
            raise RegistryError("AccessControlUnauthorizedAccount")  # Refuse.
        old = self.records.get(doc_hash)  # Existing record, if any.
        if old is None or old.status is not Status.VALID:  # Must exist and still be valid.
            raise RegistryError("NotIssued" if old is None else "AlreadyRevoked")  # Pick the matching error.
        self.records[doc_hash] = OnChainRecord(old.subject_hash, old.issuer, old.issued_at, FAKE_TIME, Status.REVOKED)  # Replace.
        return "0xfake"  # Placeholder tx hash.

    def get_record(self, doc_hash: bytes) -> OnChainRecord:  # Same signature as RegistryChain.get_record.
        """Return the record, or the all-zero NONE record if unknown."""  # Contract.
        return self.records.get(doc_hash, EMPTY)  # Default mirrors Solidity's zeroed storage.

    def issue_batch(self, root: bytes, size: int, actor: str) -> str:  # Same signature as RegistryChain.issue_batch.
        """Store a cohort root; raise RegistryError like the contract would."""  # Contract.
        if actor not in REGISTRARS:  # Role check.
            raise RegistryError("AccessControlUnauthorizedAccount")  # Refuse.
        self.batches[root] = actor  # Remember who issued it.
        return "0xfake"  # Placeholder tx hash.

    def revoke_batch_member(self, member, reason: bytes, actor: str) -> str:  # Same signature as the real adapter.
        """Revoke one cohort leaf if the proof is valid."""  # Contract.
        leaf = merkle.leaf_hash(member.doc_hash, member.subject_hash)  # Rebuild the leaf.
        if not merkle.verify_proof(member.proof, member.root, leaf):  # Must be a real member.
            raise RegistryError("InvalidProof")  # Same name as the contract error.
        self.revoked_leaves.add((member.root, leaf))  # Mark revoked.
        return "0xfake"  # Placeholder tx hash.

    def get_batch_record(self, member) -> OnChainRecord:  # Same signature as the real adapter.
        """Return VALID/REVOKED for a proven member, else the NONE record."""  # Contract.
        leaf = merkle.leaf_hash(member.doc_hash, member.subject_hash)  # Rebuild the leaf.
        if member.root not in self.batches or not merkle.verify_proof(member.proof, member.root, leaf):  # Not a member.
            return EMPTY  # Reads like an unknown document.
        revoked = (member.root, leaf) in self.revoked_leaves  # Was this leaf revoked?
        status = Status.REVOKED if revoked else Status.VALID  # Derive status.
        return OnChainRecord(member.subject_hash, self.batches[member.root], FAKE_TIME, FAKE_TIME if revoked else 0, status)  # Record.
