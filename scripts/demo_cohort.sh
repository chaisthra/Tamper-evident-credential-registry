#!/usr/bin/env bash
# Stretch-goal demo: a whole cohort issued under ONE Merkle root, then one member revoked without touching the others.
# Expects a running node (`make node`); `make demo-cohort` deploys a fresh registry first.
set -uo pipefail  # Stop on undefined variables and pipe failures; NOT -e, because some steps are meant to fail.

MANIFEST="docs/samples/cohort_2024.csv"  # CSV: pdf,student_id for three fictional students.
BUNDLES="build/bundles"  # Where the per-student proof bundles are written.
FORGED="build/degree_CS2024001_forged.pdf"  # Tampered copy of student 1's PDF.
CLI="python3 -m client.cli"  # How we call the client.

step() { printf '\n=== %s ===\n' "$1"; }  # Prints a visible heading for each demo step.

step "1. Registrar issues the whole cohort in one transaction"  # Only the root goes on-chain.
$CLI issue-cohort "$MANIFEST" --out "$BUNDLES"  # Writes build/bundles/<id>.json.

step "2. Student CS2024002 proves their degree with their bundle"  # Membership + ownership.
$CLI verify docs/samples/degree_CS2024002.pdf --bundle "$BUNDLES/CS2024002.json" --student-id CS2024002  # VALID, YES.

step "3. A forged copy of CS2024001's degree"  # One flipped bit.
python3 scripts/tamper.py docs/samples/degree_CS2024001.pdf "$FORGED"  # Write the forgery.
$CLI verify "$FORGED" --bundle "$BUNDLES/CS2024001.json"  # FAIL: leaf not in the tree.

step "4. Registrar revokes CS2024002 only"  # Per-member revocation.
$CLI revoke docs/samples/degree_CS2024002.pdf --bundle "$BUNDLES/CS2024002.json" --reason "issued in error"  # Revoke.

step "5. CS2024002 now REVOKED, CS2024003 still VALID"  # Others unaffected.
$CLI verify docs/samples/degree_CS2024002.pdf --bundle "$BUNDLES/CS2024002.json"  # REVOKED.
$CLI verify docs/samples/degree_CS2024003.pdf --bundle "$BUNDLES/CS2024003.json"  # VALID.

printf '\n=== cohort demo finished ===\n'  # End marker.
