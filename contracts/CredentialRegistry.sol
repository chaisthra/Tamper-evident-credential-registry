// SPDX-License-Identifier: MIT
// ^ Licence tag: the Solidity compiler warns if a source file does not declare one.
pragma solidity 0.8.24; // Pin one exact compiler version so every build produces identical bytecode.

// Import OpenZeppelin's audited role system instead of writing our own access control (fewer bugs to explain).
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Sha256Merkle} from "./Sha256Merkle.sol"; // Our small Merkle-proof checker (stretch goal: a whole cohort under one root).

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

    /// @notice One cohort issued with a single transaction: only its Merkle root is stored.
    struct Batch {          // Per-root record.
        address issuer;     // Registrar who issued the cohort; only they may revoke members.
        uint64 issuedAt;    // Block timestamp of the batch issue.
        uint32 size;        // Number of members, for display and auditing only.
    } // end of struct Batch

    /// @dev Merkle root => batch record. issuedAt == 0 means "no such batch".
    mapping(bytes32 => Batch) private _batches; // One storage write for a whole cohort instead of one per student.
    /// @dev Merkle root => leaf hash => revocation time; lets one member be revoked without touching the others.
    mapping(bytes32 => mapping(bytes32 => uint64)) private _memberRevokedAt; // 0 = not revoked.

    /// @notice Emitted when a registrar issues a credential; lets anyone rebuild history from logs.
    event CredentialIssued(bytes32 indexed docHash, bytes32 indexed subjectHash, address indexed issuer, uint64 issuedAt);
    /// @notice Emitted when a credential is revoked; reasonCode is a hash of the off-chain reason text.
    event CredentialRevoked(bytes32 indexed docHash, address indexed revoker, bytes32 reasonCode, uint64 revokedAt);

    /// @notice Emitted when a registrar issues a cohort under one Merkle root.
    event BatchIssued(bytes32 indexed root, address indexed issuer, uint32 size, uint64 issuedAt);
    /// @notice Emitted when one member of a cohort is revoked.
    event BatchMemberRevoked(bytes32 indexed root, bytes32 indexed leaf, address indexed revoker, bytes32 reasonCode, uint64 revokedAt);

    error ZeroAddress();              // Custom errors are cheaper than revert strings and are decoded by name in the client.
    error ZeroHash();                 // Rejects an all-zero hash, which would be indistinguishable from "empty".
    error AlreadyIssued(bytes32 docHash);  // Same PDF cannot be issued twice (also blocks re-issuing a revoked one).
    error NotIssued(bytes32 docHash);      // Cannot revoke something that was never issued.
    error AlreadyRevoked(bytes32 docHash); // Revocation is one-way and happens once.
    error NotIssuer(bytes32 docHash, address caller); // One university cannot revoke another university's credential.
    error EmptyBatch();            // A cohort must have at least one member.
    error InvalidProof();          // The Merkle proof does not lead to the stored root.

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

    /// @notice Issues a whole cohort by storing only the Merkle root of (docHash, subjectHash) leaves.
    /// @param root Merkle root built off-chain by client/merkle.py.
    /// @param size Number of members in the cohort (informational).
    /// @dev Reverts: AccessControlUnauthorizedAccount; ZeroHash; EmptyBatch; AlreadyIssued (same root twice).
    function issueBatch(bytes32 root, uint32 size) external onlyRole(REGISTRAR_ROLE) { // One transaction for N students.
        if (root == bytes32(0)) revert ZeroHash(); // Refuse an empty root.
        if (size == 0) revert EmptyBatch(); // Refuse an empty cohort.
        if (_batches[root].issuedAt != 0) revert AlreadyIssued(root); // Same root cannot be issued twice.
        uint64 nowTs = uint64(block.timestamp); // Read the block time once.
        _batches[root] = Batch(msg.sender, nowTs, size); // Store issuer, time, size.
        emit BatchIssued(root, msg.sender, size, nowTs); // Audit trail.
    } // end of issueBatch

    /// @notice Revokes one member of a cohort; the rest of the cohort stays valid.
    /// @param root The cohort's Merkle root.
    /// @param docHash SHA-256 of the member's PDF.
    /// @param subjectHash The member's salted student-id hash.
    /// @param proof Sibling hashes proving membership.
    /// @param reasonCode Hash of the off-chain reason text.
    /// @dev Reverts: AccessControlUnauthorizedAccount; NotIssued; NotIssuer; InvalidProof; AlreadyRevoked.
    function revokeBatchMember(
        bytes32 root, bytes32 docHash, bytes32 subjectHash, bytes32[] calldata proof, bytes32 reasonCode
    ) external onlyRole(REGISTRAR_ROLE) { // Parameters split over lines for readability.
        Batch storage batch = _batches[root]; // Pointer to the stored batch.
        if (batch.issuedAt == 0) revert NotIssued(root); // Unknown cohort.
        if (batch.issuer != msg.sender) revert NotIssuer(root, msg.sender); // Only the issuing registrar.
        bytes32 leafHash = Sha256Merkle.leaf(docHash, subjectHash); // Rebuild the member's leaf.
        if (!Sha256Merkle.verify(proof, root, leafHash)) revert InvalidProof(); // Must really be a member.
        if (_memberRevokedAt[root][leafHash] != 0) revert AlreadyRevoked(docHash); // Revoke once only.
        uint64 nowTs = uint64(block.timestamp); // Same time for storage and event.
        _memberRevokedAt[root][leafHash] = nowTs; // Mark just this member as revoked.
        emit BatchMemberRevoked(root, leafHash, msg.sender, reasonCode, nowTs); // Audit trail.
    } // end of revokeBatchMember

    /// @notice Checks a cohort member: NONE if the root is unknown or the proof fails, else VALID or REVOKED.
    /// @param root The cohort's Merkle root (from the student's proof bundle).
    /// @param docHash SHA-256 of the PDF being checked.
    /// @param subjectHash Salted student-id hash from the bundle.
    /// @param proof Sibling hashes from the bundle.
    /// @return A Credential struct in the same shape as verify(), so the client treats both paths alike.
    function verifyBatchMember(
        bytes32 root, bytes32 docHash, bytes32 subjectHash, bytes32[] calldata proof
    ) external view returns (Credential memory) { // Free read.
        Batch memory batch = _batches[root]; // Copy the batch record into memory.
        bytes32 leafHash = Sha256Merkle.leaf(docHash, subjectHash); // Leaf for this PDF + subject.
        if (batch.issuedAt == 0 || !Sha256Merkle.verify(proof, root, leafHash)) { // Unknown cohort or not a member...
            return Credential(bytes32(0), address(0), 0, 0, Status.NONE); // ...reads exactly like an unknown document.
        } // end of if
        uint64 revokedAt = _memberRevokedAt[root][leafHash]; // 0 if still valid.
        Status status = revokedAt == 0 ? Status.VALID : Status.REVOKED; // Derive the status.
        return Credential(subjectHash, batch.issuer, batch.issuedAt, revokedAt, status); // Same shape as verify().
    } // end of verifyBatchMember
} // end of contract CredentialRegistry
