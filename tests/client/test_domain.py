"""Client-side tests: tamper detection, revocation reporting, and the salted-hash privacy property."""  # Purpose.

import hashlib  # Used to play the attacker computing unsalted hashes.

import pytest  # Test framework (fixtures, raises).

from client import cohort, domain, hashing  # Code under test.
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


def test_salt_defeats_roll_list_brute_force():  # Privacy: the brief's "unsalted studentIdHash" trap.
    roll_list = [f"CS2024{n:03d}" for n in range(1, 201)]  # Attacker's guess list: 200 plausible ids.
    unsalted = hashlib.sha256(STUDENT.encode()).digest()  # What a naive design would put on-chain.
    salted = hashing.subject_hash(STUDENT, hashing.new_salt())  # What our design puts on-chain.
    guesses = {hashlib.sha256(sid.encode()).digest(): sid for sid in roll_list}  # Attacker hashes every id.
    assert guesses.get(unsalted) == STUDENT  # Unsalted: the student is identified instantly.
    assert salted not in guesses  # Salted: the same attack finds nothing.


def test_cohort_members_verify_tamper_fails_and_one_can_be_revoked(tmp_path):  # Stretch goal: Merkle cohort.
    chain = FakeChain()  # Empty registry.
    ids = ["CS2024001", "CS2024002", "CS2024003"]  # Three fictional students (odd count exercises the carry-up rule).
    pdfs = [tmp_path / f"{sid}.pdf" for sid in ids]  # One file per student.
    for path, sid in zip(pdfs, ids):  # Write distinct contents.
        path.write_bytes(f"%PDF-1.4 degree for {sid}".encode())  # Different bytes -> different hashes.
    receipt = cohort.issue_cohort(chain, list(zip(pdfs, ids)), "registrar")  # One root for all three.
    for path, sid in zip(pdfs, ids):  # Every member proves membership and ownership.
        result = cohort.verify_member(chain, path, receipt.bundles[sid], sid)  # Check with the student's bundle.
        assert (result.outcome, result.subject_match) == (Outcome.VALID, True)  # Valid and theirs.
    pdfs[0].write_bytes(pdfs[0].read_bytes() + b"X")  # Tamper with student 1's PDF.
    assert cohort.verify_member(chain, pdfs[0], receipt.bundles[ids[0]]).outcome is Outcome.NOT_REGISTERED  # Detected.
    cohort.revoke_member(chain, pdfs[1], receipt.bundles[ids[1]], "issued in error", "registrar")  # Revoke student 2 only.
    assert cohort.verify_member(chain, pdfs[1], receipt.bundles[ids[1]]).outcome is Outcome.REVOKED  # Revoked.
    assert cohort.verify_member(chain, pdfs[2], receipt.bundles[ids[2]]).outcome is Outcome.VALID  # Student 3 untouched.
