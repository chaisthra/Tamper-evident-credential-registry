"""All named constants and environment settings for the client live here (rule M4)."""  # One place to change settings.

import os  # Reads environment variables (set via .env / the Makefile).
from pathlib import Path  # Portable file paths.

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # Repository root: client/.. ; lets paths work from any cwd.

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")  # Local Hardhat node only; never mainnet.
NETWORK_NAME = os.environ.get("NETWORK_NAME", "localhost")  # Selects deployments/<name>.json written by deploy.js.

DEPLOYMENT_FILE = PROJECT_ROOT / "deployments" / f"{NETWORK_NAME}.json"  # Contract address + chain id from deployment.
ARTIFACT_FILE = PROJECT_ROOT / "artifacts" / "contracts" / "CredentialRegistry.sol" / "CredentialRegistry.json"  # ABI from Hardhat compile.

# Which unlocked Hardhat test account plays which actor. Indices, not keys: no secrets in the repo (rule M5).
ACCOUNT_INDEX = {  # Actor name -> index into the node's account list.
    "admin": 0,  # Deployer; can grant/remove registrars. Must match ADMIN_INDEX in scripts/deploy.js.
    "registrar": 1,  # University registrar granted REGISTRAR_ROLE by deploy.js (REGISTRAR_INDEX there).
    "outsider": 2,  # An account with no role, used to show a rejected action.
}  # end of ACCOUNT_INDEX
DEFAULT_ACTOR = "registrar"  # Who sends issue/revoke when the CLI is not told otherwise.

SALT_BYTES = 32  # 256-bit random salt per student: far too many values to brute-force.
HASH_BYTES = 32  # SHA-256 output size; matches Solidity bytes32.
READ_CHUNK_BYTES = 64 * 1024  # Hash files in 64 KiB pieces so large PDFs do not need to fit in memory.
MERKLE_LEAF_PREFIX = b"\x00"  # Must equal LEAF_PREFIX in contracts/Sha256Merkle.sol.
MERKLE_NODE_PREFIX = b"\x01"  # Must equal NODE_PREFIX in contracts/Sha256Merkle.sol.
TX_TIMEOUT_SECONDS = 30  # How long to wait for a transaction to be mined before giving up.

EXIT_OK = 0  # CLI exit code: verification VALID or command succeeded.
EXIT_NOT_VALID = 1  # CLI exit code: document tampered/unknown or revoked.
EXIT_REJECTED = 2  # CLI exit code: the chain refused the transaction (e.g. non-registrar).
