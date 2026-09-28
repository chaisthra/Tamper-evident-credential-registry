"""Command-line interface: parses arguments, calls the domain layer, prints results. Run: python -m client.cli --help"""  # Purpose.

import argparse  # Standard-library argument parser.
import csv  # Reads the cohort manifest (pdf,student_id per row).
import json  # Reads and writes proof bundles.
import sys  # For exit codes.
from datetime import datetime, timezone  # Formats Unix timestamps for people.
from pathlib import Path  # File path type.

from client import cohort, config, domain, hashing  # Settings, business rules (single + cohort), hex helpers.
from client.models import Outcome, RegistryError  # Result type and the "chain said no" error.


def _when(timestamp: int) -> str:  # Display helper.
    """Return a Unix timestamp as a readable UTC date-time string."""  # Contract.
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")  # Always UTC.


def cmd_issue(chain, args) -> int:  # Handler for `issue`.
    """Issue a credential for args.pdf / args.student_id. Returns EXIT_OK."""  # Contract.
    receipt = domain.issue_credential(chain, Path(args.pdf), args.student_id, args.actor)  # Do the work.
    print("ISSUED")  # Headline.
    print(f"  document hash : {hashing.to_hex(receipt.doc_hash)}")  # What went on-chain as the key.
    print(f"  subject hash  : {hashing.to_hex(receipt.subject_hash)}")  # Salted id hash that went on-chain.
    print(f"  salt (SECRET) : {hashing.to_hex(receipt.salt)}  <- give to the student, never on-chain")  # Off-chain secret.
    print(f"  transaction   : {receipt.tx_hash}")  # Audit reference.
    return config.EXIT_OK  # Success.


def cmd_verify(chain, args) -> int:  # Handler for `verify`.
    """Verify args.pdf (and optionally ownership). Returns EXIT_OK if VALID, else EXIT_NOT_VALID."""  # Contract.
    result = _verify(chain, args)  # Single-credential or cohort path, depending on --bundle.
    print(f"document hash : {hashing.to_hex(result.doc_hash)}")  # Show what was looked up.
    if result.outcome is Outcome.NOT_REGISTERED:  # Unknown hash.
        print("FAIL: not registered - the file was altered or never issued")  # Honest: we cannot tell which.
        return config.EXIT_NOT_VALID  # Not valid.
    print(f"{result.outcome.value}: issued {_when(result.record.issued_at)} by {result.record.issuer}")  # VALID or REVOKED.
    if result.outcome is Outcome.REVOKED:  # Add revocation time.
        print(f"  revoked {_when(result.record.revoked_at)}")  # When it stopped being valid.
    if result.subject_match is not None:  # Ownership was checked.
        print(f"  belongs to {args.student_id}: {'YES' if result.subject_match else 'NO'}")  # Result of the check.
    ok = result.outcome is Outcome.VALID and result.subject_match is not False  # Valid and not shown to belong to someone else.
    return config.EXIT_OK if ok else config.EXIT_NOT_VALID  # Exit code for scripts.


def cmd_revoke(chain, args) -> int:  # Handler for `revoke`.
    """Revoke the credential for args.pdf with args.reason. Returns EXIT_OK."""  # Contract.
    if args.bundle:  # Cohort member: revoke just this one leaf.
        tx_hash = cohort.revoke_member(chain, Path(args.pdf), _load_bundle(args.bundle), args.reason, args.actor)  # Do it.
    else:  # Single credential.
        tx_hash = domain.revoke_credential(chain, Path(args.pdf), args.reason, args.actor)  # Do the work.
    print(f"REVOKED (reason kept off-chain)\n  transaction   : {tx_hash}")  # Confirmation.
    return config.EXIT_OK  # Success.


def cmd_issue_cohort(chain, args) -> int:  # Handler for `issue-cohort`.
    """Issue every row of the manifest CSV under one Merkle root; write one bundle JSON per student. Returns EXIT_OK."""  # Contract.
    with open(args.manifest, newline="", encoding="utf-8") as handle:  # csv module wants newline="".
        members = [(Path(row["pdf"]), row["student_id"]) for row in csv.DictReader(handle)]  # Header: pdf,student_id.
    receipt = cohort.issue_cohort(chain, members, args.actor)  # Hash, build tree, one transaction.
    out_dir = Path(args.out)  # Folder for the bundles.
    out_dir.mkdir(parents=True, exist_ok=True)  # Create it if needed.
    for student_id, bundle in receipt.bundles.items():  # One file per student.
        (out_dir / f"{student_id}.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")  # Save bundle.
    print(f"COHORT ISSUED: {len(members)} credentials, one transaction")  # Headline.
    print(f"  merkle root   : {hashing.to_hex(receipt.root)}")  # The only thing stored on-chain.
    print(f"  transaction   : {receipt.tx_hash}")  # Audit reference.
    print(f"  proof bundles : {out_dir}/<student_id>.json  <- give each student theirs (contains their salt)")  # Next step.
    return config.EXIT_OK  # Success.


def _load_bundle(path: str) -> dict:  # Small helper.
    """Return the parsed proof-bundle JSON at `path`."""  # Contract.
    return json.loads(Path(path).read_text(encoding="utf-8"))  # Read + parse.


def _verify(chain, args):  # Chooses the verification path.
    """Return a VerificationResult via the cohort path if --bundle was given, else the single-credential path."""  # Contract.
    if args.bundle:  # Cohort member: salt comes from the bundle.
        return cohort.verify_member(chain, Path(args.pdf), _load_bundle(args.bundle), args.student_id)  # Merkle check.
    salt = hashing.from_hex(args.salt) if args.salt else None  # Parse the optional salt.
    return domain.verify_credential(chain, Path(args.pdf), args.student_id, salt)  # Single-credential check.


def build_parser() -> argparse.ArgumentParser:  # Defines the commands and their options.
    """Return the argument parser with issue / verify / revoke subcommands."""  # Contract.
    parser = argparse.ArgumentParser(prog="credreg", description="Tamper-evident credential registry")  # Top level.
    sub = parser.add_subparsers(dest="command", required=True)  # One subcommand must be given.
    issue = sub.add_parser("issue", help="registrar issues a credential for a PDF")  # `issue` command.
    issue.add_argument("pdf")  # Path to the certificate PDF.
    issue.add_argument("--student-id", required=True)  # Student id (hashed with a salt, never stored).
    verify = sub.add_parser("verify", help="anyone checks a PDF")  # `verify` command.
    verify.add_argument("pdf")  # Path to the PDF to check.
    verify.add_argument("--student-id")  # Optional: check ownership...
    verify.add_argument("--salt")  # ...using the salt the student was given.
    verify.add_argument("--bundle")  # Cohort member: path to the student's proof-bundle JSON.
    revoke = sub.add_parser("revoke", help="registrar revokes a credential")  # `revoke` command.
    revoke.add_argument("pdf")  # Path to the PDF being revoked.
    revoke.add_argument("--reason", required=True)  # Reason text (only its hash goes on-chain).
    revoke.add_argument("--bundle")  # Cohort member: revoke via its proof bundle.
    batch = sub.add_parser("issue-cohort", help="registrar issues a whole cohort under one Merkle root")  # Stretch goal.
    batch.add_argument("manifest")  # CSV with columns pdf,student_id.
    batch.add_argument("--out", required=True)  # Folder to write the per-student bundles into.
    for p in (issue, revoke, batch):  # Write commands need a sender.
        p.add_argument("--as", dest="actor", default=config.DEFAULT_ACTOR, choices=sorted(config.ACCOUNT_INDEX))  # Who signs.
    return parser  # Ready to parse.


HANDLERS = {"issue": cmd_issue, "verify": cmd_verify, "revoke": cmd_revoke, "issue-cohort": cmd_issue_cohort}  # Command name -> handler function.


def main(argv=None) -> int:  # Entry point.
    """Parse argv, run the command, and return an exit code (EXIT_REJECTED if the chain refuses)."""  # Contract.
    args = build_parser().parse_args(argv)  # argv=None means "use sys.argv".
    from client.chain import RegistryChain  # Imported here so --help works even without web3 or a running node.
    try:  # Chain rejections are expected outcomes in the demo, not crashes.
        return HANDLERS[args.command](RegistryChain(), args)  # Connect and dispatch.
    except RegistryError as err:  # Contract reverted.
        print(f"REJECTED by contract: {err.reason}")  # e.g. AccessControlUnauthorizedAccount.
        return config.EXIT_REJECTED  # Distinct exit code.


if __name__ == "__main__":  # Only when run as a program, not when imported by tests.
    sys.exit(main())  # Pass the exit code to the shell.
