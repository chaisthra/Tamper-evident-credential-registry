# One entry point for every task. Usage: make install | compile | test | node | deploy | demo

-include .env      # Load local settings if a .env exists (optional; defaults live in client/config.py).
export             # Pass those variables on to npx and python.

PYTHON ?= python3  # Python interpreter; override with `make PYTHON=python` on Windows.

.PHONY: install compile test node deploy demo clean  # These are commands, not files.

install:  ## Install JavaScript and Python dependencies.
	npm install                                  # Hardhat, OpenZeppelin, test tooling.
	$(PYTHON) -m pip install -r requirements.txt # web3.py and pytest.

compile:  ## Compile the Solidity contract into artifacts/ (ABI used by the client).
	npx hardhat compile

test: compile  ## Run ALL tests: contract tests on an in-process chain, then client tests.
	npx hardhat test          # tests/contract - no node needed.
	$(PYTHON) -m pytest       # tests/client - uses an in-memory fake chain.

node:  ## Start a local Hardhat chain (keep this running in its own terminal).
	npx hardhat node

deploy: compile  ## Deploy a fresh registry to the running local node.
	npx hardhat run scripts/deploy.js --network localhost

demo: deploy  ## Fresh deployment, then the scripted end-to-end demo.
	bash scripts/demo.sh

clean:  ## Remove build output.
	rm -rf artifacts cache deployments build
