# Tamper-evident credential registry

A registrar issues a degree certificate. The PDF is hashed off-chain, and only
`(docHash, subjectHash, issuer, issuedAt, revokedAt, status)` goes on-chain.
Anyone can verify a PDF they were handed by re-hashing it. Changing a single byte makes verification fail.
A revoked credential reads **REVOKED**, not absent. Only accounts with `REGISTRAR_ROLE` can issue or revoke.

Runs on a **local Hardhat chain only**. It uses no real funds and no real personal data: the sample certificates are fictional.

## Prerequisites

- Node.js 18+ and npm
- Python 3.10+
- `make` (on Windows, run the commands inside each Makefile target by hand)

## Run it

```bash
make install     # npm install + pip install -r requirements.txt
make test        # compiles the contract, runs 10 contract tests + 5 client tests
```

Demo (two terminals):

```bash
make node        # terminal 1: local chain on http://127.0.0.1:8545, leave running
make demo        # terminal 2: fresh deploy, then issue -> verify -> tamper -> revoke -> reject
make demo-cohort # terminal 2: stretch goal - 3 students under one Merkle root, revoke one, others stay valid
```

Optional: `cp .env.example .env` to change the RPC URL. The defaults work without it.

## Expected demo output (abridged)

```
=== 2. Verifier checks the genuine PDF ===
VALID: issued 2026-09-28 07:44:12 UTC by 0x7099...79C8
=== 4. Verifier checks the forged PDF ===
FAIL: not registered - the file was altered or never issued
=== 6. Verifier checks the genuine PDF again ===
REVOKED: issued ... revoked ...
=== 7. A non-registrar tries to issue ===
REJECTED by contract: AccessControlUnauthorizedAccount
```

## CLI

```bash
python3 -m client.cli issue  <pdf> --student-id <id> [--as registrar|admin|outsider]
python3 -m client.cli verify <pdf> [--student-id <id> --salt <hex>]   # ownership check is optional
python3 -m client.cli revoke <pdf> --reason "<text>" [--as ...]

# Stretch goal: a whole cohort under one Merkle root (manifest CSV columns: pdf,student_id)
python3 -m client.cli issue-cohort docs/samples/cohort_2024.csv --out build/bundles
python3 -m client.cli verify <pdf> --bundle build/bundles/<id>.json [--student-id <id>]
python3 -m client.cli revoke <pdf> --bundle build/bundles/<id>.json --reason "<text>"
```

Exit codes: `0` = OK or VALID, `1` = not registered or revoked, `2` = rejected by the contract.

## Layout

```
contracts/CredentialRegistry.sol   on-chain rules: roles, issue, revoke, verify, cohort batch functions
contracts/Sha256Merkle.sol         Merkle proof check (SHA-256, sorted pairs, leaf/node prefixes)
scripts/deploy.js                  deploy + grant REGISTRAR_ROLE, writes deployments/<network>.json
scripts/demo.sh, demo_cohort.sh    scripted demos
scripts/tamper.py                  one-byte forgery helper
client/config.py                   every constant and setting (M4)
client/models.py                   plain data types shared by layers
client/hashing.py                  SHA-256 of files, salted student-id hash, reason codes
client/chain.py                    the only module that imports web3 (M3)
client/domain.py                   issue / verify / revoke rules, no web3
client/merkle.py, client/cohort.py Merkle tree + proofs; cohort issue / verify / revoke
client/cli.py                      argument parsing and printing
tests/contract/                    Hardhat tests (in-process chain)
tests/client/                      pytest tests (in-memory fake chain)
docs/samples/                      fictional certificate PDFs + cohort manifest
docs/slides/                       7-slide deck (.pptx + .pdf)
DESIGN.md, AI_USAGE.md             design rationale, rejected options, threats; AI declaration
```

## Known limits

- Re-saving or re-printing a genuine PDF changes its bytes. The copy then fails verification even though it is genuine.
- A tampered file and a never-issued file look the same on-chain (the hash is unknown), so the tool reports "not registered" for both.
- The chain proves who issued a credential and whether it was revoked. It does not prove the degree was earned.
- Anyone who knows a student's id **and** salt can link that student to their credential. If the salt leaks, that link can be made.
- Every node and account is a Hardhat development account. There is no production key management.
