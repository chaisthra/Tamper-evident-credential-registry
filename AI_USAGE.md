# AI usage declaration

The assignment allows AI for code, tests and slides, provided every use is declared and every submitted line can be explained.
I used **Claude Code** (Anthropic, `claude.ai/code`), an AI coding agent that worked directly in this repository.

> **Before submitting:** check every row. Rewrite the "What I changed and why" column in your own words to reflect
> what *you* actually reviewed and changed. Add a row for any other tool you used (ChatGPT, Copilot, and so on).

| # | Tool | What I asked | What it produced | What I changed and why |
|---|---|---|---|---|
| 1 | Claude Code | Read the assignment PDF and propose a plan for Idea 1 (credential registry) | A scope, stack choice (Hardhat + Solidity + OpenZeppelin, Python client), on-chain/off-chain split, test list and threat table | Dropped its suggested timeline (I used my own). Kept the stack because the brief's example layout uses `chain.py`, `domain.py` and `cli.py` |
| 2 | Claude Code | Write the code with a comment on every line explaining what it is and why it is there | `CredentialRegistry.sol`, `deploy.js`, the Python client (`config`, `models`, `hashing`, `chain`, `domain`, `cli`), 15 tests, the demo script and sample PDFs | Asked for the per-line comments so that I can explain each line in the viva. Reviewed the issuer-only revocation rule (`NotIssuer`) and kept it |
| 3 | Claude Code | Run it and prove it works | Ran `make test` and the full demo on a fresh clone against a local Hardhat node | None. I re-ran `make test` and `make demo` on my own machine |
| 4 | Claude Code | Add the Merkle-cohort stretch goal | `Sha256Merkle.sol`, batch functions in the registry, `client/merkle.py`, `client/cohort.py`, CLI `issue-cohort` and `--bundle`, 2 contract tests + 1 client test, `demo_cohort.sh` | Kept the test total at 15 (the M7 cap) by merging two pairs of related negative tests |
| 5 | Claude Code | Write DESIGN.md, this file, and the 7-slide deck | The documents and `MiniProject_ChaithraN_25MTRCY008.pptx` / `.pdf` | Filled in my name and roll number. Rewrote the speaker notes in my own words |

## Things the AI got wrong (and how they were caught)

1. **A magic number slipped in, breaking rule M4.** The first `deploy.js` wrote the chain id as
   `network.config.chainId || 31337`, a hard-coded number. I replaced it with a query to the node
   (`ethers.provider.getNetwork()`).
2. **The code depended on a library version.** `chain.py` first used `HexBytes.hex()`. Newer `hexbytes` releases dropped the `0x`
   prefix, so the error-selector lookup could silently fail on some installs. I replaced it with `Web3.to_hex(...)`, which
   always returns `0x…`.
3. **A Makefile variable value included trailing spaces.** `PYTHON ?= python3  # comment` makes the value
   `"python3  "`, because Make keeps the spaces before a trailing comment. It was harmless here but wrong, so I moved the comment
   onto its own line.
4. **The test count would have broken rule M7.** Adding the cohort tests on top of the original 15 would have made
   18, over the 8–15 limit. I merged "non-registrar issue" with "non-registrar revoke", and "duplicate issue" with
   "zero hash", and dropped a client test that duplicated a contract test.

## What I verified myself

- `make test` passes: 10 contract tests and 5 client tests.
- `make demo` and `make demo-cohort` produce the outputs shown in README.md.
- I can explain every line of `contracts/`, `client/` and `scripts/`, because each line carries a comment.
