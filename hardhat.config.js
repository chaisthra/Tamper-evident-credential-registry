// Hardhat configuration: how to compile the contract, where tests live, which chain to talk to.
require("@nomicfoundation/hardhat-toolbox"); // Loads ethers, chai matchers (revertedWithCustomError), and the test runner.

const SOLC_VERSION = "0.8.24"; // Must match the `pragma solidity` line in the contract.
const OPTIMIZER_RUNS = 200; // Standard optimiser setting: balances deployment cost against call cost.
const DEFAULT_RPC_URL = "http://127.0.0.1:8545"; // Where `npx hardhat node` listens by default.

module.exports = { // Hardhat reads this exported object.
  solidity: { // Compiler settings.
    version: SOLC_VERSION, // Exact compiler, for reproducible bytecode.
    settings: { optimizer: { enabled: true, runs: OPTIMIZER_RUNS } }, // Turn on the optimiser.
  }, // end of solidity
  paths: { tests: "tests/contract" }, // Contract tests live under tests/, as the assignment layout asks.
  networks: { // Named chains we can deploy to.
    localhost: { url: process.env.RPC_URL || DEFAULT_RPC_URL }, // Local chain only - never mainnet (ethics rule).
  }, // end of networks
}; // end of module.exports
