// Deploys CredentialRegistry to the local chain and grants the registrar role to one test account.
// Run with: npx hardhat run scripts/deploy.js --network localhost
const fs = require("fs"); // Node file-system module, used to write the deployment record.
const path = require("path"); // Builds file paths that work on every OS.
const { ethers, network } = require("hardhat"); // Hardhat's ethers instance and the network we were started with.

const ADMIN_INDEX = 0; // Test account #0 becomes the admin (manages who is a registrar).
const REGISTRAR_INDEX = 1; // Test account #1 is the university registrar used in the demo.
const DEPLOYMENTS_DIR = path.join(__dirname, "..", "deployments"); // Folder the Python client reads from.
const DEPLOYMENT_FILE = path.join(DEPLOYMENTS_DIR, `${network.name}.json`); // e.g. deployments/localhost.json.

/**
 * Deploys the registry, grants REGISTRAR_ROLE, and saves the address for the client.
 * Takes nothing; returns a Promise that resolves when done; throws if any transaction fails.
 */
async function main() { // async because every chain call returns a Promise.
  const signers = await ethers.getSigners(); // The node's unlocked test accounts (no private keys in our code).
  const admin = signers[ADMIN_INDEX]; // Signer object for the admin account.
  const registrar = signers[REGISTRAR_INDEX]; // Signer object for the registrar account.
  const factory = await ethers.getContractFactory("CredentialRegistry", admin); // Compiled bytecode + ABI, sent from admin.
  const registry = await factory.deploy(admin.address); // Sends the deployment transaction (constructor arg = admin).
  await registry.waitForDeployment(); // Waits until it is mined.
  const role = await registry.REGISTRAR_ROLE(); // Reads the role id from the contract rather than recomputing it here.
  await (await registry.grantRole(role, registrar.address)).wait(); // Admin grants the role; wait for mining.
  const { chainId } = await ethers.provider.getNetwork(); // Ask the node which chain it is (no hard-coded id).
  const record = { address: await registry.getAddress(), chainId: Number(chainId) }; // What the client needs; BigInt -> Number for JSON.
  fs.mkdirSync(DEPLOYMENTS_DIR, { recursive: true }); // Create the folder if it does not exist yet.
  fs.writeFileSync(DEPLOYMENT_FILE, JSON.stringify(record, null, 2)); // Save address + chain id as pretty JSON.
  console.log(`CredentialRegistry deployed at ${record.address}`); // Human-readable confirmation.
  console.log(`Registrar role granted to ${registrar.address}`); // Shows which account can issue.
} // end of main

main().catch((err) => { // Run main; if anything throws, report it.
  console.error(err); // Print the error for the user.
  process.exitCode = 1; // Non-zero exit so `make` stops.
}); // end of error handler
