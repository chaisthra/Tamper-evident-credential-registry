# DESIGN — Tamper-evident credential registry

## 1. Problem and "why blockchain?"

Degree certificates are easy to forge and slow to verify. An employer receives a PDF and then has to email the
university or pay a verification agency, and wait days for an answer. Concrete failure: a candidate edits
"Second Class" to "First Class" in a genuine PDF. The document looks perfect, and the employer has no cheap way to tell.

| Question from the brief | Answer |
|---|---|
| Who are the mutually distrusting writers? | Several universities (registrars) write to one shared registry. None of them should be able to edit, backdate or delete another's records, and none of them should run the registry for the others. Verifiers (employers, other universities, embassies) trust neither the student nor the paper. |
| Which intermediary is removed? | The verification agency and the "email the registrar and wait" loop. Anyone can re-hash the PDF and read the registry for free, at any time, without asking anyone. |
| Would a plain database with signatures do? | **Partly, and we say so.** A signed PDF already proves which university issued it. What signatures alone do not give is a *revocation status that the issuer cannot silently rewrite*. Revocations and issue times sit in one append-only, publicly replicated log that no single university controls. See rejected option A below. |

## 2. Architecture

```
          Registrar (university)                         Verifier (employer)            Student
                 │  PDF + student id                         │  PDF (+ bundle / salt)       │
                 ▼                                           ▼                              │
   ┌──────────────────────── client (Python, off-chain) ───────────────────────────┐        │
   │ cli.py ──► domain.py / cohort.py ──► hashing.py, merkle.py (pure hashlib)       │◄───────┘
   │                    │                                                            │ salt / proof bundle
   │                    ▼                                                            │ (kept by the student)
   │               chain.py  (the ONLY web3 import)                                  │
   └────────────────────┬───────────────────────────────────────────────────────────┘
                        │ JSON-RPC (local Hardhat node only)
                        ▼
   ┌──────────────── CredentialRegistry.sol (on-chain) ────────────────┐
   │ AccessControl: DEFAULT_ADMIN_ROLE ─ grants ─► REGISTRAR_ROLE       │
   │ _credentials[docHash]  → {subjectHash, issuer, issuedAt, revokedAt, status}
   │ _batches[root]         → {issuer, issuedAt, size}   (Sha256Merkle) │
   │ _memberRevokedAt[root][leaf] → time                                │
   │ events: CredentialIssued / CredentialRevoked / BatchIssued / BatchMemberRevoked
   └────────────────────────────────────────────────────────────────────┘
```

**Actors:** the admin (deployer, a multisig in production), registrars (universities), verifiers (anyone), and students.

## 3. On-chain vs off-chain split

| Data | Where | Why |
|---|---|---|
| `docHash` = SHA-256(PDF bytes) | on-chain (key) | Public fingerprint. It reveals nothing about the content, and one changed byte changes it completely. |
| `subjectHash` = SHA-256(salt ‖ studentId) | on-chain | Binds the credential to a student without revealing them. The 32-byte random salt defeats roll-list brute force (see test `test_salt_defeats_roll_list_brute_force`). |
| `issuer`, `issuedAt`, `revokedAt`, `status` | on-chain | This is the part that must be tamper-proof and publicly readable. |
| Merkle root of a cohort | on-chain | One storage write for N students. |
| The PDF, name, student id | **off-chain** | Personal data. The chain is permanent and public, so there is no "right to erasure". |
| Salt, Merkle proof ("proof bundle") | off-chain, held by the student | Only the student decides who can link the credential to them. |
| Revocation reason text | off-chain (only its hash goes on-chain) | The reason may be sensitive. Its hash lets it be proven later. |

## 4. Module map

| File | Responsibility (rule M1) |
|---|---|
| `contracts/CredentialRegistry.sol` | Roles, issue/revoke/verify, cohort issue/revoke/verify |
| `contracts/Sha256Merkle.sol` | Merkle leaf/node hashing and proof check (SHA-256, sorted pairs, domain-separated) |
| `scripts/deploy.js` | Deploys the registry, grants `REGISTRAR_ROLE`, and writes `deployments/<network>.json` |
| `client/config.py` | Every constant and setting (M4) |
| `client/models.py` | Plain data types shared between layers |
| `client/hashing.py` | File hash, salt, subject hash, reason code |
| `client/merkle.py` | Builds trees and proofs, mirroring `Sha256Merkle.sol` |
| `client/chain.py` | The only web3 import (M3). Decodes reverts into error names |
| `client/domain.py` | Single-credential issue/verify/revoke rules |
| `client/cohort.py` | Cohort issue, member verify and member revoke |
| `client/cli.py` | Argument parsing and output |
| `scripts/demo.sh`, `scripts/demo_cohort.sh`, `scripts/tamper.py` | Scripted demos and the one-byte forgery helper |
| `tests/contract/*.test.js`, `tests/client/*.py` | 10 + 5 tests, 9 of them negative |

## 5. Data model and contract interface

```solidity
enum Status { NONE, VALID, REVOKED }          // NONE first: an unknown hash reads as NONE
struct Credential { bytes32 subjectHash; address issuer; uint64 issuedAt; uint64 revokedAt; Status status; }

issue(bytes32 docHash, bytes32 subjectHash)                     onlyRole(REGISTRAR_ROLE)
revoke(bytes32 docHash, bytes32 reasonCode)                     onlyRole(REGISTRAR_ROLE), issuer only
verify(bytes32 docHash) view returns (Credential)               never reverts

issueBatch(bytes32 root, uint32 size)                           onlyRole(REGISTRAR_ROLE)
revokeBatchMember(root, docHash, subjectHash, proof, reasonCode) onlyRole(REGISTRAR_ROLE), issuer only, valid proof
verifyBatchMember(root, docHash, subjectHash, proof) view returns (Credential)

errors: ZeroAddress, ZeroHash, AlreadyIssued, NotIssued, AlreadyRevoked, NotIssuer, EmptyBatch, InvalidProof,
        AccessControlUnauthorizedAccount (OpenZeppelin)
```

Key rules:
- **Revoked is not absent.** Records are never deleted. A revoked hash cannot be re-issued, because it keeps its REVOKED history.
- **Only the issuing registrar can revoke.** One university cannot revoke another university's credential (`NotIssuer`).
- **The cohort Merkle tree** uses leaf = SHA-256(0x00 ‖ docHash ‖ subjectHash) and node = SHA-256(0x01 ‖ min ‖ max).
  The prefixes stop an inner node being passed off as a leaf. Sorting the pair removes the need for left/right flags. An odd node is carried up unchanged. Proof length is capped at 32.

## 6. Measured gas (local Hardhat node)

| Call | Gas |
|---|---|
| Deploy | 1,033,949 |
| `issue` (1 credential) | 94,210 |
| `issueBatch` (whole cohort, any size) | 49,317 |
| `revoke` | 34,568 |
| `revokeBatchMember` | 57,940 |
| `verify` / `verifyBatchMember` | 0 (view call) |

A cohort of 60 students costs about 5.65 M gas one at a time, or about 49 k gas as a single batch.

## 7. Rejected options

**A. Signed PDFs plus a university-run revocation list (no blockchain).** The university signs each PDF with its key
and publishes a CRL-style list of revoked certificates on its own website. This is cheaper and simpler, and it is how
TLS certificates work. *Rejected because:*
- Each university fully controls its own list. It can silently remove a revocation, backdate an entry, or take the list offline, and a verifier cannot tell.
- A verifier has to find and trust N different endpoints.

The honest middle ground is an append-only transparency log (like Certificate Transparency). It would be a reasonable alternative if the universities agreed to run log monitors.

**B. Store the full record on-chain (name, roll number, degree, grade, or the PDF itself).** *Rejected because:*
- Everything on-chain is public and cannot be erased, which is irreversible exposure of personal data.
- Storage costs gas per 32-byte word.
- It adds nothing to verification: the hash already proves the PDF has not changed.

**C. Unsalted `studentIdHash = hash(rollNumber)`.** *Rejected because:* roll numbers follow a pattern, so hashing a
list of 200 candidates finds the student instantly. The test `test_salt_defeats_roll_list_brute_force` shows this.

## 8. Threats, controls and residual risk

| Threat | Control | Residual risk |
|---|---|---|
| A registrar's key is stolen and used to issue fake degrees | `REGISTRAR_ROLE` is required. The admin can remove the role (tested). Every record stores its `issuer` | Fakes issued before detection stay VALID until the real registrar revokes them. In production the admin should be a multisig |
| A student is linked to a credential by brute-forcing `subjectHash` | Per-student 32-byte random salt, and no personal data on-chain | If the salt or proof bundle leaks, that student can be linked. Hashes stay on-chain forever |
| Someone deploys a look-alike registry and issues "valid" fakes | Verifiers use the official contract address published by the university consortium (`deployments/*.json`) | Trust moves to how that address is distributed |

## 9. Limits at scale and known gaps

- Re-saving or re-printing a genuine PDF changes its bytes, so the copy fails verification. The registry proves "this exact file", not "this content".
- A tampered file and a never-issued file look the same on-chain (an unknown hash).
- The registry proves who issued a credential and when. It does not prove the degree was earned (an oracle problem).
- Registrar onboarding is centralised in one admin. A real consortium would govern roles by vote.
- On a public chain, each `issue` costs about 94 k gas. Batching makes a cohort cost about the same as a single issue.
