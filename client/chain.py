"""The ONLY module that talks to the blockchain (rule M3). Everything else sees plain Python types."""  # Module purpose.

import json  # Reads the ABI artifact and the deployment record.

from web3 import Web3  # Ethereum client library; imported nowhere else in the client.
from web3.exceptions import ContractCustomError, ContractLogicError  # Raised when a call/transaction reverts.

from client import config  # Addresses, file paths, timeouts.
from client.models import OnChainRecord, RegistryError, Status  # Plain types returned to the domain layer.


def _load_json(path) -> dict:  # Small helper to avoid repeating open/json.load.
    """Return the parsed JSON at `path`. Raises FileNotFoundError with a hint if it is missing."""  # Contract.
    if not path.exists():  # Common mistake: forgot to compile or deploy.
        raise FileNotFoundError(f"{path} not found - run `make compile` and `make deploy` first")  # Actionable message.
    with open(path, encoding="utf-8") as handle:  # Text mode, explicit encoding.
        return json.load(handle)  # Parsed dictionary.


def _error_selectors(abi: list) -> dict:  # Builds a lookup to turn revert data into an error name.
    """Return {4-byte selector hex: error name} for every custom error in the ABI."""  # Contract.
    selectors = {}  # Result dictionary.
    for item in abi:  # Walk every ABI entry.
        if item.get("type") != "error":  # Only custom errors matter here.
            continue  # Skip functions, events, constructor.
        signature = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"  # e.g. "NotIssued(bytes32)".
        selectors[Web3.to_hex(Web3.keccak(text=signature)[:4])[2:]] = item["name"]  # First 4 bytes identify the error; drop "0x".
    return selectors  # Filled lookup table.


class RegistryChain:  # Adapter: wraps web3 calls behind a small, testable interface.
    """Connects to the deployed CredentialRegistry and exposes issue / revoke / get_record."""  # Class purpose.

    def __init__(self) -> None:  # Builds the connection from config; takes no arguments.
        """Connect to RPC_URL and load the contract. Raises ConnectionError if the node is not running."""  # Contract.
        self._w3 = Web3(Web3.HTTPProvider(config.RPC_URL))  # HTTP connection to the local node.
        if not self._w3.is_connected():  # Fail early with a clear message instead of a stack trace later.
            raise ConnectionError(f"cannot reach {config.RPC_URL} - is `make node` running?")  # Actionable message.
        abi = _load_json(config.ARTIFACT_FILE)["abi"]  # Function/event/error definitions from the compiled contract.
        address = _load_json(config.DEPLOYMENT_FILE)["address"]  # Where deploy.js put the contract.
        self._contract = self._w3.eth.contract(address=address, abi=abi)  # web3 contract object.
        self._selectors = _error_selectors(abi)  # For decoding reverts into names.

    def account(self, actor: str) -> str:  # Maps an actor name to a node account address.
        """Return the address for actor ('admin', 'registrar', 'outsider'). Raises KeyError for unknown actors."""  # Contract.
        return self._w3.eth.accounts[config.ACCOUNT_INDEX[actor]]  # Unlocked dev account; no private key handled here.

    def issue(self, doc_hash: bytes, subject_hash: bytes, actor: str) -> str:  # On-chain write #1.
        """Send issue(docHash, subjectHash) from `actor`. Returns the tx hash. Raises RegistryError on revert."""  # Contract.
        return self._send(self._contract.functions.issue(doc_hash, subject_hash), actor)  # Build call, then send.

    def revoke(self, doc_hash: bytes, reason: bytes, actor: str) -> str:  # On-chain write #2.
        """Send revoke(docHash, reasonCode) from `actor`. Returns the tx hash. Raises RegistryError on revert."""  # Contract.
        return self._send(self._contract.functions.revoke(doc_hash, reason), actor)  # Build call, then send.

    def get_record(self, doc_hash: bytes) -> OnChainRecord:  # On-chain read (free, no transaction).
        """Return the stored record for doc_hash; status is NONE if it was never issued."""  # Contract.
        subject, issuer, issued_at, revoked_at, status = self._contract.functions.verify(doc_hash).call()  # Struct -> tuple.
        return OnChainRecord(bytes(subject), issuer, issued_at, revoked_at, Status(status))  # Convert to plain types.

    def _send(self, fn, actor: str) -> str:  # Shared transaction path for issue and revoke.
        """Transact `fn` from `actor` and wait for mining. Returns tx hash hex. Raises RegistryError on revert."""  # Contract.
        try:  # web3 estimates gas first, which surfaces reverts before anything is mined.
            tx_hash = fn.transact({"from": self.account(actor)})  # Node signs with its unlocked account.
        except (ContractCustomError, ContractLogicError) as err:  # The contract refused the call.
            raise RegistryError(self._decode(err)) from err  # Translate to a readable name for the domain layer.
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=config.TX_TIMEOUT_SECONDS)  # Wait for mining.
        if receipt.status != 1:  # 1 = success; 0 = reverted after mining (should not happen after gas estimation).
            raise RegistryError("TransactionFailed")  # Still report it cleanly.
        return Web3.to_hex(tx_hash)  # 0x-prefixed hex string for display.

    def _decode(self, err: Exception) -> str:  # Turns raw revert data into e.g. "AlreadyIssued".
        """Return the custom error name for a revert, or the raw message if it cannot be decoded."""  # Contract.
        data = str(getattr(err, "data", None) or err.args[0])  # web3 puts the revert data in .data (or the message).
        for selector, name in self._selectors.items():  # Try every known error selector.
            if selector in data:  # The revert data starts with the 4-byte selector.
                return name  # Found it.
        return str(err)  # Unknown revert: show whatever web3 said.
