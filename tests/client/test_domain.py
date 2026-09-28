"""Client-side tests: tamper detection, revocation reporting, and the salted-hash privacy property."""  # Purpose.

import hashlib  # Used to play the attacker computing unsalted hashes.

import pytest  # Test framework (fixtures, raises).

from client import domain, hashing  # Code under test.
from client.models import Outcome, RegistryError  # Expected result values.
from tests.client.fake_chain import FakeChain  # Deterministic in-memory chain.

STUDENT = "CS2024001"  # Fictional student id (no real personal data - ethics rule).


@pytest.fixture  # pytest calls this and passes the result to tests that name it.
def pdf(tmp_path):  # tmp_path = a fresh temporary folder per test, supplied by pytest.
    """Write a small fake certificate file and return its path."""  # Contract.
    path = tmp_path / "degree.pdf"  # File name inside the temp folder.
    path.write_bytes(b"%PDF-1.4\nCertificate: M.Tech CSE, fictional student\n%%EOF\n")  # Fixed bytes = deterministic hash.
    return path  # Given to the test.


def test_issue_then_verify_is_valid_and_owned(pdf):  # Happy path including the ownership check.
    chain = FakeChain()  # Empty registry.
    receipt = domain.issue_credential(chain, pdf, STUDENT, "registrar")  # Registrar issues.
    result = domain.verify_credential(chain, pdf, STUDENT, receipt.salt)  # Verifier checks with id + salt.
    assert result.outcome is Outcome.VALID  # Genuine file is valid.
    assert result.subject_match is True  # And it belongs to this student.


def test_one_changed_byte_is_not_registered(pdf, tmp_path):  # Negative: the core tamper-evidence claim.
    chain = FakeChain()  # Empty registry.
    domain.issue_credential(chain, pdf, STUDENT, "registrar")  # Issue the genuine file.
    data = bytearray(pdf.read_bytes())  # Copy the bytes so we can edit them.
    data[len(data) // 2] ^= 0x01  # Flip the lowest bit of one byte in the middle.
    forged = tmp_path / "forged.pdf"  # New file for the altered copy.
    forged.write_bytes(bytes(data))  # Save it.
    assert domain.verify_credential(chain, forged).outcome is Outcome.NOT_REGISTERED  # Detected.


def test_revoked_reads_revoked_and_cannot_be_revoked_twice(pdf):  # Revoked is not the same as absent.
    chain = FakeChain()  # Empty registry.
    domain.issue_credential(chain, pdf, STUDENT, "registrar")  # Issue.
    domain.revoke_credential(chain, pdf, "issued in error", "registrar")  # Revoke.
    assert domain.verify_credential(chain, pdf).outcome is Outcome.REVOKED  # Reports REVOKED, not NOT_REGISTERED.
    with pytest.raises(RegistryError, match="AlreadyRevoked"):  # Negative: second revoke must fail.
        domain.revoke_credential(chain, pdf, "again", "registrar")  # Attempt.


def test_outsider_cannot_issue(pdf):  # Negative: access control seen from the client side.
    with pytest.raises(RegistryError, match="AccessControlUnauthorizedAccount"):  # Expected rejection.
        domain.issue_credential(FakeChain(), pdf, STUDENT, "outsider")  # Outsider tries to issue.


def test_salt_defeats_roll_list_brute_force():  # Privacy: the brief's "unsalted studentIdHash" trap.
    roll_list = [f"CS2024{n:03d}" for n in range(1, 201)]  # Attacker's guess list: 200 plausible ids.
    unsalted = hashlib.sha256(STUDENT.encode()).digest()  # What a naive design would put on-chain.
    salted = hashing.subject_hash(STUDENT, hashing.new_salt())  # What our design puts on-chain.
    guesses = {hashlib.sha256(sid.encode()).digest(): sid for sid in roll_list}  # Attacker hashes every id.
    assert guesses.get(unsalted) == STUDENT  # Unsalted: the student is identified instantly.
    assert salted not in guesses  # Salted: the same attack finds nothing.
