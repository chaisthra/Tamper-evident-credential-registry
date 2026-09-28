#!/usr/bin/env bash
# Scripted demo from the brief: issue -> verify OK -> change one byte -> FAIL -> revoke -> REVOKED -> non-registrar rejected.
# Expects a running node (`make node`) and a fresh deployment (`make demo` does the deploy for you).
set -uo pipefail  # Stop on undefined variables and pipe failures; NOT -e, because some steps are meant to fail.

GENUINE="docs/samples/degree_CS2024001.pdf"  # Fictional certificate committed to the repo.
OTHER="docs/samples/degree_CS2024002.pdf"  # A second fictional certificate for the outsider attempt.
FORGED="build/degree_CS2024001_forged.pdf"  # Tampered copy written by scripts/tamper.py.
CLI="python3 -m client.cli"  # How we call the client.

step() { printf '\n=== %s ===\n' "$1"; }  # Prints a visible heading for each demo step.

step "1. Registrar issues the credential"  # Happy path starts.
$CLI issue "$GENUINE" --student-id CS2024001  # Registrar account (default actor) issues.

step "2. Verifier checks the genuine PDF"  # Should be VALID.
$CLI verify "$GENUINE"  # Anyone can run this; it is a free read.

step "3. Someone changes one byte"  # Forgery attempt.
python3 scripts/tamper.py "$GENUINE" "$FORGED"  # Writes the altered copy.

step "4. Verifier checks the forged PDF"  # Should FAIL.
$CLI verify "$FORGED"  # Different hash -> not registered.

step "5. Registrar revokes the credential"  # Revocation.
$CLI revoke "$GENUINE" --reason "issued in error"  # Reason text stays off-chain.

step "6. Verifier checks the genuine PDF again"  # Should be REVOKED, not absent.
$CLI verify "$GENUINE"  # Shows REVOKED with times.

step "7. A non-registrar tries to issue"  # Should be rejected by the contract.
$CLI issue "$OTHER" --student-id CS2024002 --as outsider  # Outsider account has no role.

printf '\n=== demo finished ===\n'  # End marker.
