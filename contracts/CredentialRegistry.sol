// SPDX-License-Identifier: MIT
// ^ Licence tag: the Solidity compiler warns if a source file does not declare one.
pragma solidity 0.8.24; // Pin one exact compiler version so every build produces identical bytecode.

// Import OpenZeppelin's audited role system instead of writing our own access control (fewer bugs to explain).
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title CredentialRegistry
/// @notice Stores only fingerprints of degree certificates so anyone can check a PDF they were handed.
/// @dev The PDF, the student's name and ID all stay off-chain; only hashes, times, issuer and status live here.
contract CredentialRegistry is AccessControl { // Inherit AccessControl to get grantRole/revokeRole/hasRole/onlyRole.
    /// @notice Role identifier for universities allowed to issue and revoke credentials.
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE"); // Roles in OZ are bytes32 ids; hashing a name is the convention.

    /// @notice Life-cycle of a credential. NONE must stay first so an unknown hash reads as NONE (default 0).
    enum Status { // An enum is stored as a small integer, cheaper and clearer than strings.
        NONE,     // 0: never issued - this is what the default (empty) storage slot means.
        VALID,    // 1: issued and currently valid.
        REVOKED   // 2: issued, later revoked - kept forever so it reads "revoked", not "absent".
    } // end of enum Status

    /// @notice Everything the chain knows about one credential.
    struct Credential {       // Groups the fields so one mapping lookup returns the whole record.
        bytes32 subjectHash;  // SHA-256(salt || studentId), computed off-chain; salted so a roll list cannot reverse it.
        address issuer;       // Which registrar account issued it; only that account may later revoke it.
        uint64 issuedAt;      // Block timestamp at issue; uint64 is enough until year ~5e11 and packs with the address.
        uint64 revokedAt;     // Block timestamp at revocation, 0 while still valid.
        Status status;        // NONE / VALID / REVOKED as defined above.
    } // end of struct Credential

    /// @dev docHash (SHA-256 of the PDF bytes) => its record. Private so reads go through verify().
    mapping(bytes32 => Credential) private _credentials; // A mapping gives O(1) lookup by hash with no loops (no unbounded gas).

    /// @notice Emitted when a registrar issues a credential; lets anyone rebuild history from logs.
    event CredentialIssued(bytes32 indexed docHash, bytes32 indexed subjectHash, address indexed issuer, uint64 issuedAt);
    /// @notice Emitted when a credential is revoked; reasonCode is a hash of the off-chain reason text.
    event CredentialRevoked(bytes32 indexed docHash, address indexed revoker, bytes32 reasonCode, uint64 revokedAt);

    error ZeroAddress();              // Custom errors are cheaper than revert strings and are decoded by name in the client.
    error ZeroHash();                 // Rejects an all-zero hash, which would be indistinguishable from "empty".
    error AlreadyIssued(bytes32 docHash);  // Same PDF cannot be issued twice (also blocks re-issuing a revoked one).
    error NotIssued(bytes32 docHash);      // Cannot revoke something that was never issued.
    error AlreadyRevoked(bytes32 docHash); // Revocation is one-way and happens once.
    error NotIssuer(bytes32 docHash, address caller); // One university cannot revoke another university's credential.

    /// @notice Deploys the registry and makes `admin` the only account able to grant or remove registrars.
    /// @param admin Account that receives DEFAULT_ADMIN_ROLE (a multisig in production).
    /// @dev Reverts with ZeroAddress if admin is the zero address (the registry would be unmanageable forever).
    constructor(address admin) { // Runs once at deployment.
        if (admin == address(0)) revert ZeroAddress(); // Guard: a zero admin would lock role management permanently.
        _grantRole(DEFAULT_ADMIN_ROLE, admin); // OZ internal call: admin can now grantRole(REGISTRAR_ROLE, ...).
    } // end of constructor

    /// @notice Records a new credential as VALID.
    /// @param docHash SHA-256 of the exact PDF bytes.
    /// @param subjectHash SHA-256(salt || studentId) computed off-chain.
    /// @dev Reverts: AccessControlUnauthorizedAccount if caller lacks REGISTRAR_ROLE; ZeroHash; AlreadyIssued.
    function issue(bytes32 docHash, bytes32 subjectHash) external onlyRole(REGISTRAR_ROLE) { // onlyRole = the permission check.
        if (docHash == bytes32(0) || subjectHash == bytes32(0)) revert ZeroHash(); // Refuse empty inputs.
        if (_credentials[docHash].status != Status.NONE) revert AlreadyIssued(docHash); // No overwrite, even of a revoked record.
        uint64 nowTs = uint64(block.timestamp); // Read the block time once; the cast is safe for billions of years.
        _credentials[docHash] = Credential(subjectHash, msg.sender, nowTs, 0, Status.VALID); // Write the full record in one go.
        emit CredentialIssued(docHash, subjectHash, msg.sender, nowTs); // Public, append-only audit trail.
    } // end of issue

    /// @notice Marks an issued credential as REVOKED; the record is kept, never deleted.
    /// @param docHash SHA-256 of the PDF being revoked.
    /// @param reasonCode Hash of the off-chain reason text (keeps the reason private but provable).
    /// @dev Reverts: AccessControlUnauthorizedAccount; NotIssued; AlreadyRevoked; NotIssuer.
    function revoke(bytes32 docHash, bytes32 reasonCode) external onlyRole(REGISTRAR_ROLE) { // Only registrars can revoke.
        Credential storage cred = _credentials[docHash]; // `storage` = pointer to the stored record, so edits persist.
        if (cred.status == Status.NONE) revert NotIssued(docHash); // Nothing to revoke.
        if (cred.status == Status.REVOKED) revert AlreadyRevoked(docHash); // Already revoked; keep the first revocation time.
        if (cred.issuer != msg.sender) revert NotIssuer(docHash, msg.sender); // Only the issuing registrar may revoke.
        uint64 nowTs = uint64(block.timestamp); // Same timestamp for storage and event.
        cred.status = Status.REVOKED; // Flip status; the record stays so verify() shows REVOKED rather than NONE.
        cred.revokedAt = nowTs; // Remember when it stopped being valid.
        emit CredentialRevoked(docHash, msg.sender, reasonCode, nowTs); // Audit trail for revocations.
    } // end of revoke

    /// @notice Returns the stored record for a document hash (status NONE if never issued).
    /// @param docHash SHA-256 of the PDF someone wants to check.
    /// @return The Credential struct; never reverts, so verifiers always get an answer.
    function verify(bytes32 docHash) external view returns (Credential memory) { // `view` = free to call, no transaction.
        return _credentials[docHash]; // Unknown hashes return an all-zero struct, i.e. status NONE.
    } // end of verify
} // end of contract CredentialRegistry
