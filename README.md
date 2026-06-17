# Blockchain-Based Health Insurance Management System for ALU

A fully functional, cryptographically secure blockchain node written entirely in C. This project implements a hybrid architecture that combines an Ethereum-style Account Model for user balances and strict replay protection, with a Bitcoin-style UTXO Model for institutional insurance pool settlements.

## System Overview
The ALU Health Insurance Blockchain operates as a dual-engine decentralized ledger. It simultaneously processes token transfers via an Account-Balance Model and settles complex insurance pool payouts using a UTXO Model.

## Key Features
* **True Cryptography:** Implements OpenSSL `secp256k1` ECDSA for transaction signing and verification. Public keys are derived from private keys to prevent OpenSSL 3.0 hardware fault attacks.

* **Dual-Ledger System:** 
    * **Account Model:** Members and providers maintain balances and a strict Nonce to prevent replay attacks (`sender_nonce == account_nonce + 1`).

  * **UTXO Model:** The Insurance Pool uses Unspent Transaction Outputs to prevent double-spending during claim settlements.

* **Proof-of-Work Consensus:** Custom mining algorithm with SHA-256 block hashing and automatic difficulty retargeting every 10 blocks (targeting a 30-90 second block time).

* **Mathematical Immutability:** Blocks are linked via recursive `previous_hash` pointers, and transactions are hashed into a Merkle Tree from scratch.

* **Automated Fraud Engine:** The mempool automatically flags transactions as `SUSPICIOUS` if they trigger high-frequency (3+ claims in 24h), abnormal amount (>2x historical average), or duplicate ID rules.

* **Disk Persistence:** The entire chain state, mempool, UTXO set, and policy roster are serialized to a binary `.bin` file and securely loaded on startup.

## Prerequisites

To compile and run this application, your system must have the following installed:
* **GCC (GNU Compiler Collection):** To compile the C source code.
* **OpenSSL Development Library:** Required for the cryptographic hashing functions.
  * Ubuntu/Debian: `sudo apt-get install libssl-dev`
  * CentOS/RHEL: `sudo yum install openssl-devel`
  * macOS (Homebrew): `brew install openssl`

## Compilation and Setup
* Clone or download this repository to your local machine.

* Compile the source code. Note: Use gcc and link the OpenSSL crypto library (-lcrypto). Run the following command in your terminal:
`gcc -Wall -Wextra -o blockchain_core blockchain_core.c -lcrypto`

## Running the Program
Execute the compiled program: `./blockchain_core`

## The Startup Blockade
If the node loads a pre-existing chain state from disk (`alu_chain_state.bin`), all commands are locked by default. You must run the cryptographic audit to mathematically verify the chain's integrity before interacting: `alu-chain> blockchain_verify`

## Command Line Interface (CLI)
The node features a fully interactive Command-Line Interface. Type help in the terminal to see all available commands.

### Membership & Accounts

* **register_member <id> <balance>**: Generates a secp256k1 keypair and registers a new wallet.

* **wallet_balance <id>**: Displays the AHT balance and current Replay Nonce.

* **account_transfer <from> <to> <amount>**: Transfers AHT directly between wallets.

### Insurance & Policies
* **enroll_policy <member_id> <policy_id> <plan_tier>**: Enrolls a member for exactly 365 days.

* **pay_premium <member_id> <amount>**: Deducts AHT from the member, routes 5% to the Reinsurance Pool, and creates a UTXO for the Main Pool.

* **submit_claim <provider_id> <member_id> <amount>**: Signs a claim request with the provider's private key and routes it to the mempool.

* **settle_claim <provider_id> <amount>**:Consumes UTXOs to pay the provider. Automatically splits the cost with the Reinsurance Pool if the amount exceeds 1,000 AHT.

### Blockchain & Mining
* **mempool_view**: Displays all **PENDING**, **CONFIRMED**, and **SUSPICIOUS** transactions.

* **mine_solo**: Assembles the top priority transactions, computes the Merkle Root, solves the PoW hash, and mints a block reward to the miner.

* **mine_pool**: Distributes the block reward proportionally between simulated pool miners.

* **difficulty_status**: Shows the current required leading zeros and the active block reward.

* **blockchain_verify**: Re-hashes every block, rebuilds all Merkle Trees, and cryptographically verifies every historic ECDSA signature.

### UTXO & Audit
* **utxo_view**: Displays all active Unspent Transaction Outputs owned by the Insurance Pool.

* **transaction_history**: Displays a complete audit log of all confirmed transactions on the chain.

* **fraud_review**: Displays transactions withheld from the mempool queue due to failed fraud heuristics.

## Ledger Initialization & Account Setup
1. Verify the auto-generated system identities exist with default balances
* `account_balance INSURANCE_POOL`
* `account_balance REINSURANCE_POOL`
* `account_balance MINER_SOLO_01`
-------
2. Register new members (Generates secp256k1 keypairs)
* `register_member ALUMEM_001 50000`
* `register_member KIGALI_HOSP 0`
------
3. Confirm their accounts were written to the state ledger
* `view_member ALUMEM_001`
* `account_balance ALUMEM_001`

## Policy Lifecycle & UTXO Generation
1. Enroll the new member under a coverage plan
* `enroll_policy ALUMEM_001 POL_992 BASIC`
-----
2. Inspect the policy to confirm status is ACTIVE and expiry is set to +365 days
* `view_policy POL_992`
* `policy_status POL_992`
-----
3. Pay a premium
* `pay_premium ALUMEM_001 2000`
-----
4. Check the account balances to ensure the 5% split was executed properly
* `account_balance ALUMEM_001`
* `reinsurance_balance`
-----
5. Verify the Bitcoin-style UTXO was successfully generated for the Insurance Pool
* `utxo_view`

## Mempool Management & Priority Queuing
1. Create a baseline token transfer with a low fee
* `account_transfer ALUMEM_001 KIGALI_HOSP 100 1`
-----
2. Create a second token transfer with a higher fee to jump the queue
* `account_transfer ALUMEM_001 KIGALI_HOSP 50 10`
-----
3. Create a third transaction with an identical fee to the second one to test timestamp ordering
* `account_transfer ALUMEM_001 KIGALI_HOSP 25 10`
-----
4. View the mempool to ensure it is correctly sorted (Fee: 10, Fee: 10, Fee: 1)
* `mempool_view`

## Fraud Engine & Input Validation
1. Test Input Validation: Attempt a transfer exceeding the available 
* `account balance`
* `account_transfer ALUMEM_001 KIGALI_HOSP 9999999 5`
-----
2. Test Fraud Heuristic (Abnormal Amount): Submit an excessively large claim 
* `submit_claim KIGALI_HOSP ALUMEM_001 15000`
-----
3. Audit the fraud queue to find your suspicious transaction ID
* `fraud_review`
-----
4. Attempt to mine (The suspicious transaction must remain stuck in the mempool and NOT be mined)
* `mine_solo`
* `mempool_view`
-----
5. Clear the fraud block by executing a manual override
* `approve_suspicious <tx_id>`

## Proof-of-Work Mining & Difficulty Adjustment
1. Inspect the initial block configurations
* `difficulty_status`
-----
2. Execute a mining loop (Aggregates the pending txs, computes Merkle tree, solves PoW)
* `mine_solo`
-----
3. Verify that the mempool has been cleared of confirmed transactions
* `mempool_view`
-----
4. View the updated blockchain structural data
* `blockchain_view`
-----
5. Verify the miner wallet received its configured AHT block reward injection
* `account_balance MINER_SOLO_01`

## Insurance Settlements & Split Payments
1. Simulate clinical infrastructure operations
* `service_request ALUMEM_001 KIGALI_HOSP`
* `preauth_request ALUMEM_001 KIGALI_HOSP 2500`
* `preauth_approve <preauth_id>`
-----
2. Submit the high-value claim through the provider portal
* `submit_claim KIGALI_HOSP ALUMEM_001 2500`
* `approve_claim <claim_id>`
-----
3. Mine the approved system transactions into the blockchain ledger
* `mine_solo`
-----
4. Execute the settlement 
* `settle_claim KIGALI_HOSP 2500`
-----
5. Audit the resulting state alterations across models
* `account_balance KIGALI_HOSP`
* `reinsurance_balance`
* `utxo_view`

## Disk Persistence & Tamper Detection Auditing
1. Commit the complete network state to the binary storage layer
* `chain_save`
-----
2. Force an immediate reload from disk to verify serialization routines
* `chain_load`
-----
3. Run the complete cryptographic validation suite
* `blockchain_verify`
-----
4. Check historical transaction trails to ensure structural continuity
* `transaction_history`
* `premium_history`
* `claim_history`

## Technical Implementation Details
* **Hex Parsing & Memory Safety:** Uses strtol to strictly parse hex arrays into bytes, preventing OpenSSL padding corruption on 64-bit architectures.

* **Account Nonce vs. Block Nonce:** The system strictly separates the Block Nonce (used purely for PoW hashing) from the Account Nonce (used for Ethereum-style transaction ordering and replay protection).

* **System Transactions:** Administrative actions (e.g., preauth_request, approve_claim) are not mocked; they generate actual signed transactions originating from the INSURANCE_POOL wallet and are stored permanently on-chain.
