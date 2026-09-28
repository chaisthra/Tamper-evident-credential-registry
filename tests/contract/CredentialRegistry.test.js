// Contract tests: run on Hardhat's in-process chain, so they are fast and deterministic.
const { expect } = require("chai"); // Assertion library bundled with hardhat-toolbox.
const { ethers } = require("hardhat"); // Hardhat's ethers, pointed at the in-process chain.
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers"); // Snapshot/restore for a clean state per test.

const STATUS = { NONE: 0n, VALID: 1n, REVOKED: 2n }; // Mirrors the Solidity enum order; `n` = BigInt, as ethers returns.
const DOC = ethers.id("degree-alice.pdf bytes"); // A stand-in 32-byte document hash (keccak of a label is fine for tests).
const OTHER_DOC = ethers.id("degree-bob.pdf bytes"); // A second, different document hash.
const SUBJECT = ethers.id("salt||CS2024001"); // A stand-in 32-byte salted student-id hash.
const REASON = ethers.id("issued in error"); // A stand-in 32-byte reason-code hash.

/**
 * Deploys a fresh registry and grants REGISTRAR_ROLE to two university accounts.
 * Returns the contract plus named signers; used by loadFixture so each test starts from the same snapshot.
 */
async function deployFixture() { // Runs once; later calls restore the snapshot instead of redeploying.
  const [admin, registrar, registrar2, outsider] = await ethers.getSigners(); // Four test accounts with clear roles.
  const registry = await ethers.deployContract("CredentialRegistry", [admin.address]); // Deploy with admin as constructor arg.
  const role = await registry.REGISTRAR_ROLE(); // Role id read from the contract.
  await registry.grantRole(role, registrar.address); // University A.
  await registry.grantRole(role, registrar2.address); // University B (to test cross-university revocation).
  return { registry, role, admin, registrar, registrar2, outsider }; // Everything tests need.
} // end of deployFixture

describe("CredentialRegistry", function () { // Groups all contract tests under one name.
  it("issues a credential that verifies as VALID with the right fields and event", async function () { // Happy path.
    const { registry, registrar } = await loadFixture(deployFixture); // Clean chain.
    await expect(registry.connect(registrar).issue(DOC, SUBJECT)) // Registrar sends issue().
      .to.emit(registry, "CredentialIssued") // The audit event must fire...
      .withArgs(DOC, SUBJECT, registrar.address, (t) => t > 0n); // ...with our values and a non-zero timestamp.
    const cred = await registry.verify(DOC); // Read back the record (free view call).
    expect(cred.status).to.equal(STATUS.VALID); // Now valid.
    expect(cred.subjectHash).to.equal(SUBJECT); // Subject hash stored unchanged.
    expect(cred.issuer).to.equal(registrar.address); // Issuer recorded.
  }); // end of test

  it("reports NONE for a document that was never issued", async function () { // What a tampered PDF looks like on-chain.
    const { registry } = await loadFixture(deployFixture); // Clean chain.
    const cred = await registry.verify(OTHER_DOC); // Ask about an unknown hash.
    expect(cred.status).to.equal(STATUS.NONE); // Absent reads as NONE.
  }); // end of test

  it("revokes a credential so it reads REVOKED, not absent", async function () { // The brief's key requirement.
    const { registry, registrar } = await loadFixture(deployFixture); // Clean chain.
    await registry.connect(registrar).issue(DOC, SUBJECT); // Issue first.
    await expect(registry.connect(registrar).revoke(DOC, REASON)) // Then revoke.
      .to.emit(registry, "CredentialRevoked"); // Revocation event must fire.
    const cred = await registry.verify(DOC); // Read back.
    expect(cred.status).to.equal(STATUS.REVOKED); // REVOKED...
    expect(cred.issuedAt).to.be.greaterThan(0n); // ...and the original issue record is still there.
    expect(cred.revokedAt).to.be.greaterThan(0n); // Revocation time recorded.
  }); // end of test

  it("rejects issue() from a non-registrar", async function () { // Negative: access control on issue.
    const { registry, role, outsider } = await loadFixture(deployFixture); // Clean chain.
    await expect(registry.connect(outsider).issue(DOC, SUBJECT)) // Outsider tries to issue.
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount") // OZ's error...
      .withArgs(outsider.address, role); // ...naming who was refused and which role was missing.
  }); // end of test

  it("rejects revoke() from a non-registrar", async function () { // Negative: access control on revoke.
    const { registry, registrar, outsider } = await loadFixture(deployFixture); // Clean chain.
    await registry.connect(registrar).issue(DOC, SUBJECT); // A real credential exists.
    await expect(registry.connect(outsider).revoke(DOC, REASON)) // Outsider tries to revoke it.
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount"); // Refused.
  }); // end of test

  it("rejects issuing the same document twice", async function () { // Negative: no overwrite.
    const { registry, registrar } = await loadFixture(deployFixture); // Clean chain.
    await registry.connect(registrar).issue(DOC, SUBJECT); // First issue succeeds.
    await expect(registry.connect(registrar).issue(DOC, SUBJECT)) // Second issue of same hash...
      .to.be.revertedWithCustomError(registry, "AlreadyIssued"); // ...is refused.
  }); // end of test

  it("rejects revoking an unknown or already-revoked document", async function () { // Negative: revoke preconditions.
    const { registry, registrar } = await loadFixture(deployFixture); // Clean chain.
    await expect(registry.connect(registrar).revoke(DOC, REASON)) // Revoke before issue...
      .to.be.revertedWithCustomError(registry, "NotIssued"); // ...is refused.
    await registry.connect(registrar).issue(DOC, SUBJECT); // Now issue it.
    await registry.connect(registrar).revoke(DOC, REASON); // Revoke once - fine.
    await expect(registry.connect(registrar).revoke(DOC, REASON)) // Revoke again...
      .to.be.revertedWithCustomError(registry, "AlreadyRevoked"); // ...is refused.
  }); // end of test

  it("rejects all-zero hashes", async function () { // Negative: input validation.
    const { registry, registrar } = await loadFixture(deployFixture); // Clean chain.
    await expect(registry.connect(registrar).issue(ethers.ZeroHash, SUBJECT)) // Zero document hash...
      .to.be.revertedWithCustomError(registry, "ZeroHash"); // ...refused.
  }); // end of test

  it("stops one university revoking another university's credential", async function () { // Negative: issuer-only revoke.
    const { registry, registrar, registrar2 } = await loadFixture(deployFixture); // Clean chain.
    await registry.connect(registrar).issue(DOC, SUBJECT); // University A issues.
    await expect(registry.connect(registrar2).revoke(DOC, REASON)) // University B tries to revoke it...
      .to.be.revertedWithCustomError(registry, "NotIssuer"); // ...refused.
  }); // end of test

  it("blocks a registrar after the admin removes their role", async function () { // Key-compromise response.
    const { registry, role, admin, registrar } = await loadFixture(deployFixture); // Clean chain.
    await registry.connect(admin).revokeRole(role, registrar.address); // Admin removes the (say, stolen) registrar key.
    await expect(registry.connect(registrar).issue(DOC, SUBJECT)) // The old key tries to issue...
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount"); // ...refused.
  }); // end of test
}); // end of describe
