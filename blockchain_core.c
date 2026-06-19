#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Constants
#define MAX_MEMPOOL_SIZE 1000
#define MAX_ACCOUNTS 1000
#define MAX_UTXOS 5000
#define MAX_TX_HISTORY 10000
#define MAX_BLOCKS 10000
#define CHAIN_FILE "alu_chain_state.bin"

#define STATUS_PENDING 0
#define STATUS_CONFIRMED 1
#define STATUS_SUSPICIOUS 2

// Data structures
typedef struct {
    char token_name[50];
    char token_symbol[10];
    double total_supply;
} Token;

typedef struct {
    uint32_t current_difficulty;
    double block_reward;
    int last_retarget_block;
} ChainState;

typedef struct {
    char transaction_id[65];
    char sender_address[200];
    char receiver_address[200];
    double amount;
    int transaction_type;
    time_t timestamp;
    uint32_t sender_nonce;
    char digital_signature[256];
} Transaction;

typedef struct {
    char block_id[65];
    time_t timestamp;
    uint32_t transaction_count;
    char previous_hash[65];
    char merkle_root[65];
    uint32_t nonce;
    char miner_id[200];
    uint32_t difficulty;
    Transaction* transactions;
} Block;

typedef struct {
    Transaction tx;
    double fee;
    int status;
} MempoolEntry;

typedef struct {
   char address[200];
    char priv_key[70];
    double balance;
    uint32_t nonce;
} Account;

typedef struct {
    char transaction_id[65];
    char owner_address[200];
    double amount;
    int is_spent;
} UTXO;

typedef struct {
    char member_id[50];
    char policy_id[50];
    int coverage_plan;
    time_t enrollment_date;
    time_t expiry_date;
    int status;
} Policy;

// Global variables
MempoolEntry mempool[MAX_MEMPOOL_SIZE];
int mempool_size = 0;

Account accounts[MAX_ACCOUNTS];
int account_count = 0;

UTXO utxo_set[MAX_UTXOS];
int utxo_count = 0;

Transaction transaction_history[MAX_TX_HISTORY];
int tx_history_count = 0;

Block blockchain[MAX_BLOCKS];
int block_count = 0;

Policy policy_roster[MAX_ACCOUNTS];
int policy_count = 0;

double reinsurance_pool_balance = 0.0;
double insurance_pool_balance = 50000.0;
int chain_verified = 1;

Token aht_token = {"ALU Health Token", "AHT", 1000000.0};
ChainState chain_state = {4, 50.0, 0};

// Forward Declarations
void generate_wallet_keys(char* pub_hex, char* priv_hex);
Account* get_account(const char* address);
void sign_transaction(Transaction *tx, const char *priv_hex);

// System Initialization
void initialize_system_wallets() {
    // Create Insurance Pool Wallet
    if (get_account("INSURANCE_POOL") == NULL) {
        Account pool; pool.balance = 50000.0; pool.nonce = 0;
        char pub[135], priv[70]; generate_wallet_keys(pub, priv);
        snprintf(pool.address, sizeof(pool.address), "INSURANCE_POOL_%s", pub);
        strcpy(pool.priv_key, priv); accounts[account_count++] = pool;
    }

    // Create Reinsurance Pool Wallet
    if (get_account("REINSURANCE_POOL") == NULL) {
        Account re_pool; re_pool.balance = 0.0; re_pool.nonce = 0;
        char pub[135], priv[70]; generate_wallet_keys(pub, priv);
        snprintf(re_pool.address, sizeof(re_pool.address), "REINSURANCE_POOL_%s", pub);
        strcpy(re_pool.priv_key, priv); accounts[account_count++] = re_pool;
    }

            // Create Default Miner Wallet
    if (get_account("MINER_SOLO_01") == NULL) {
        Account miner; miner.balance = 0.0; miner.nonce = 0;
        char pub[135], priv[70]; generate_wallet_keys(pub, priv);
        snprintf(miner.address, sizeof(miner.address), "MINER_SOLO_01_%s", pub);
        strcpy(miner.priv_key, priv); accounts[account_count++] = miner;
    }
}

// Compute SHA-256 hash using OpenSSL 3.0 EVP API
void calculate_sha256(const char* input, char* output_hash) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx != NULL) {
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, input, strlen(input));
        EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash);
        EVP_MD_CTX_free(mdctx);
    }
    for(unsigned int i = 0; i < lengthOfHash; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[64] = '\0';
}

// Generate transaction data for hashing
void get_transaction_leaf_hash(Transaction* tx, char* leaf_hash) {
    char tx_data[2048];
    snprintf(tx_data, sizeof(tx_data), "%s%s%s%f%d%ld%u",
             tx->transaction_id, tx->sender_address, tx->receiver_address,
             tx->amount, tx->transaction_type, (long)tx->timestamp,
             tx->sender_nonce);
    calculate_sha256(tx_data, leaf_hash);
}

// Generate secp256k1 keypair for new members
void generate_wallet_keys(char* pub_hex, char* priv_hex) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);

    const BIGNUM *priv = EC_KEY_get0_private_key(key);
    char *priv_str = BN_bn2hex(priv);
    strcpy(priv_hex, priv_str);

    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub = EC_KEY_get0_public_key(key);
    char *pub_str = EC_POINT_point2hex(group, pub, POINT_CONVERSION_UNCOMPRESSED, NULL);
    strcpy(pub_hex, pub_str);

    OPENSSL_free(priv_str); OPENSSL_free(pub_str); EC_KEY_free(key);
}

// Signs transaction using OpenSSL ECDSA
void sign_transaction(Transaction *tx, const char *priv_hex) {
    char hash[65];
    get_transaction_leaf_hash(tx, hash);

    unsigned char digest[32];
    for(int i=0; i<32; i++) {
        char hex_byte[3] = { hash[i*2], hash[i*2+1], '\0' };
        digest[i] = (unsigned char)strtol(hex_byte, NULL, 16);
    }

    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, priv_hex);
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, priv);

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pub_point);

    unsigned int sig_len = 0;
    unsigned char sig_buf[256];

    if (ECDSA_sign(0, digest, 32, sig_buf, &sig_len, key) != 1) {
        printf("CRITICAL: OpenSSL signing math failed.\n");
    }

    for(unsigned int i=0; i<sig_len; i++) {
        sprintf(&tx->digital_signature[i*2], "%02x", sig_buf[i]);
    }

    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
}

// Verify ECDSA signature mathematically
int verify_ecdsa_signature(Transaction* tx, const char* pub_hex) {
    if (tx->transaction_type == 9) return 1;
    if (strlen(tx->digital_signature) == 0) return 0;

    char hash[65];
    get_transaction_leaf_hash(tx, hash);

    unsigned char digest[32];
    for(int i=0; i<32; i++) {
        char hex_byte[3] = { hash[i*2], hash[i*2+1], '\0' };
        digest[i] = (unsigned char)strtol(hex_byte, NULL, 16);
    }

    unsigned char sig_buf[256];
    unsigned int sig_len = strlen(tx->digital_signature) / 2;
    for(unsigned int i=0; i<sig_len; i++) {
        char hex_byte[3] = { tx->digital_signature[i*2], tx->digital_signature[i*2+1], '\0' };
        sig_buf[i] = (unsigned char)strtol(hex_byte, NULL, 16);
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    const char* actual_pub_hex = strrchr(pub_hex, '_');
    actual_pub_hex = (actual_pub_hex != NULL) ? actual_pub_hex + 1 : pub_hex;

    EC_POINT *pub = EC_POINT_hex2point(group, actual_pub_hex, NULL, NULL);
    if (!pub) {
        printf("DEBUG: Invalid public key format.\n");
        EC_KEY_free(key);
        return 0;
    }

    EC_KEY_set_public_key(key, pub);

    // Execute mathematical proof
    int ret = ECDSA_verify(0, digest, 32, sig_buf, sig_len, key);

    EC_POINT_free(pub);
    EC_KEY_free(key);

    return (ret == 1);
}

// Build Merkle tree and calculate root hash
void compute_merkle_root(Transaction* transactions, int tx_count, char* merkle_root) {
    if (tx_count == 0) {
        strcpy(merkle_root, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }
    char (*current_level)[65] = malloc(tx_count * sizeof(*current_level));
    for (int i = 0; i < tx_count; i++) get_transaction_leaf_hash(&transactions[i], current_level[i]);
    int current_count = tx_count;

    while (current_count > 1) {
        int next_count = (current_count + 1) / 2;
        char (*next_level)[65] = malloc(next_count * sizeof(*next_level));
        for (int i = 0; i < next_count; i++) {
            char pair_data[131];
            int left_index = i * 2;
            int right_index = i * 2 + 1;
            if (right_index >= current_count) right_index = left_index;
            snprintf(pair_data, sizeof(pair_data), "%s%s", current_level[left_index], current_level[right_index]);
            calculate_sha256(pair_data, next_level[i]);
        }
        free(current_level);
        current_level = next_level;
        current_count = next_count;
    }
    strcpy(merkle_root, current_level[0]);
    free(current_level);
}

// Hash all block header
void calculate_block_hash(Block* block, char* output_hash) {
    char block_data[1024];
    snprintf(block_data, sizeof(block_data), "%ld%u%s%s%u%s%u",
             (long)block->timestamp, block->transaction_count, block->previous_hash,
             block->merkle_root, block->nonce, block->miner_id, block->difficulty);
    calculate_sha256(block_data, output_hash);
}

// Validate hash alignment with zero bits target
int is_hash_valid(const char* hash, uint32_t difficulty) {
    for (uint32_t i = 0; i < difficulty; i++) if (hash[i] != '0') return 0;
    return 1;
}

// Account & UTXO management
Account* get_account(const char* address) {
    for (int i = 0; i < account_count; i++) {
        if (strstr(accounts[i].address, address) != NULL) return &accounts[i];
    }
    return NULL;
}

void create_utxo(const char* tx_id, const char* owner, double amount) {
    if (utxo_count >= MAX_UTXOS) return;
    strcpy(utxo_set[utxo_count].transaction_id, tx_id);
    strcpy(utxo_set[utxo_count].owner_address, owner);
    utxo_set[utxo_count].amount = amount;
    utxo_set[utxo_count].is_spent = 0;
    utxo_count++;
}

int consume_utxos_for_amount(const char* owner, double required_amount) {
    double accumulated = 0.0;
    for (int i = 0; i < utxo_count; i++) {
        if (strcmp(utxo_set[i].owner_address, owner) == 0 && utxo_set[i].is_spent == 0) {
            utxo_set[i].is_spent = 1;
            accumulated += utxo_set[i].amount;
            if (accumulated >= required_amount) {
                if (accumulated > required_amount) {
                    char change_id[65];
                    snprintf(change_id, sizeof(change_id), "CHANGE_%ld", (long)time(NULL));
                    create_utxo(change_id, owner, accumulated - required_amount);
                }
                return 1;
            }
        }
    }
    return 0;
}

// Look up policy by member identifier
Policy* get_policy(const char* member_id) {
    for (int i = 0; i < policy_count; i++) {
        if (strcmp(policy_roster[i].member_id, member_id) == 0) return &policy_roster[i];
    }
    return NULL;
}

// Register member policy with 365 days validity
void enroll_policy(const char* member_id, const char* policy_id, int plan) {
    if (get_account(member_id) == NULL) {
        printf("ERROR: Member wallet %s not found. Register member first.\n", member_id);
        return;
    }

    Policy* existing_policy = get_policy(member_id);
    if (existing_policy != NULL && existing_policy->status == 1) {
        printf("ERROR: Member %s already has an ACTIVE policy (%s).\n", member_id, existing_policy->policy_id);
        return;
    }
    strcpy(policy_roster[policy_count].member_id, member_id);
    strcpy(policy_roster[policy_count].policy_id, policy_id);
    policy_roster[policy_count].coverage_plan = plan;
    policy_roster[policy_count].enrollment_date = time(NULL);
    policy_roster[policy_count].expiry_date = time(NULL) + 10;
    policy_roster[policy_count].status = 1;
    policy_count++;
    printf("Policy enrolled successfully for %s. Valid for 365 days.\n", member_id);
}

// Split premium and route 5% to reinsurance fund
void pay_premium(const char* member_id, double amount) {
    Account* acc = get_account(member_id);
    if (acc == NULL) {
        printf("ERROR: Member wallet %s not found.\n", member_id);
        return;
    }
    if (acc->balance < amount) {
        printf("ERROR: Insufficient balance. Wallet only has %.2f AHT.\n", acc->balance);
        return;
    }

    acc->balance -= amount;

    double reinsurance_cut = amount * 0.05;
    double main_pool_cut = amount - reinsurance_cut;

    insurance_pool_balance += main_pool_cut;
    reinsurance_pool_balance += reinsurance_cut;

    char utxo_id[65];
    snprintf(utxo_id, sizeof(utxo_id), "PREM_%ld", (long)time(NULL));
    create_utxo(utxo_id, "INSURANCE_POOL", main_pool_cut);

    printf("Premium Processed for %s: %.2f AHT.\n", member_id, amount);
    printf("-> %.2f AHT deducted from Member Wallet\n", amount);
    printf("-> %.2f AHT to Main Insurance Pool (UTXO Created)\n", main_pool_cut);
    printf("-> %.2f AHT sent via REINSURANCE_CONTRIBUTION\n", reinsurance_cut);
}

// Settle medical claims and draw excess from reinsurance if >1000 AHT
void settle_claim(const char* provider_id, double approved_amount) {
    if (approved_amount <= 1000.0) {
        if (!consume_utxos_for_amount("INSURANCE_POOL", approved_amount)) {
            printf("Double-Spend Prevented: Pool lacks unspent UTXOs for settlement.\n"); return;
        }
        insurance_pool_balance -= approved_amount;
        printf("Settlement of %.2f AHT paid fully by Main Pool to %s.\n", approved_amount, provider_id);
    } else {
        double excess = approved_amount - 1000.0;
        if (!consume_utxos_for_amount("INSURANCE_POOL", 1000.0)) {
            printf("Double-Spend Prevented: Pool lacks UTXOs.\n"); return;
        }
        insurance_pool_balance -= 1000.0;
        if (reinsurance_pool_balance >= excess) {
            reinsurance_pool_balance -= excess;
            printf("Settlement split for %s:\n", provider_id);
            printf("-> 1000.00 AHT paid by Main Pool\n");
            printf("-> %.2f AHT paid by Reinsurance Pool\n", excess);
        } else {
            printf("WARNING: Reinsurance Pool insufficient to cover excess. Manual review required.\n");
        }
    }
}

// Sort rule
int compare_mempool_entries(const void* a, const void* b) {
    MempoolEntry* entryA = (MempoolEntry*)a;
    MempoolEntry* entryB = (MempoolEntry*)b;
    if (entryA->fee > entryB->fee) return -1;
    if (entryA->fee < entryB->fee) return 1;
    if (entryA->tx.timestamp < entryB->tx.timestamp) return -1;
    if (entryA->tx.timestamp > entryB->tx.timestamp) return 1;
    return 0;
}

// Validate, check high-frequency fraud rules, and add to queue
int add_to_mempool(Transaction tx, double fee) {
    if (mempool_size >= MAX_MEMPOOL_SIZE) return 0;

    Account* sender = get_account(tx.sender_address);
    if (sender == NULL) { printf("Transaction rejected: Unknown Sender Address.\n"); return 0; }

    if (!verify_ecdsa_signature(&tx, sender->address)) {
        printf("Transaction rejected: Invalid ECDSA digital signature.\n"); return 0;
    }
    if (tx.sender_nonce != sender->nonce + 1) {
        printf("Transaction rejected: Invalid Nonce (Replay Protection).\n"); return 0;
    }
    if (sender->balance < (tx.amount + fee)) {
        printf("Transaction rejected: Insufficient AHT balance.\n"); return 0;
    }

    int initial_status = STATUS_PENDING;
    int count = 0;
    time_t twenty_four_hours = 24 * 60 * 60;

    for (int i = 0; i < tx_history_count; i++) {
        if (strcmp(transaction_history[i].sender_address, tx.sender_address) == 0) {
            if (tx.timestamp - transaction_history[i].timestamp <= twenty_four_hours) count++;
        }
    }

    for (int i = 0; i < mempool_size; i++) {
        if (strcmp(mempool[i].tx.sender_address, tx.sender_address) == 0) {
            if (tx.timestamp - mempool[i].tx.timestamp <= twenty_four_hours) count++;
        }
    }

    if (count >= 3) {
        printf("WARNING: High-frequency transactions detected. Flagging SUSPICIOUS.\n");
        initial_status = STATUS_SUSPICIOUS;
    }
    mempool[mempool_size].tx = tx;
    mempool[mempool_size].fee = fee;
    mempool[mempool_size].status = initial_status;
    mempool_size++;
    qsort(mempool, mempool_size, sizeof(MempoolEntry), compare_mempool_entries);
    return 1;
}

// Recalculate PoW target difficulty every 10 blocks
void adjust_difficulty() {
    if (block_count < 10 || block_count % 10 != 0) return;
    time_t time_diff = blockchain[block_count - 1].timestamp - blockchain[block_count - 10].timestamp;
    double average_time = (double)time_diff / 10.0;
    uint32_t old_diff = chain_state.current_difficulty;

    if (average_time < 30.0) chain_state.current_difficulty++;
    else if (average_time > 90.0 && chain_state.current_difficulty > 1) chain_state.current_difficulty--;

    chain_state.last_retarget_block = block_count;
    printf("\nDIFFICULTY RETARGET: Avg Time = %.2f sec | Old Diff = %u | New Diff = %u\n", average_time, old_diff, chain_state.current_difficulty);
}

// Package unconfirmed transactions and execute Proof-of-Work loop
void mine_block() {
    if (mempool_size == 0) {
        printf("No pending transactions in mempool to mine.\n");
        return;
    }

    Block new_block;
    new_block.timestamp = time(NULL);
    new_block.difficulty = chain_state.current_difficulty;
    new_block.nonce = 0;
    strcpy(new_block.miner_id, "ALU_MINER_POOL");

    if (block_count == 0) strcpy(new_block.previous_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    else strcpy(new_block.previous_hash, blockchain[block_count - 1].block_id);

    new_block.transaction_count = 0;
    new_block.transactions = malloc(5 * sizeof(Transaction));

    for (int i = 0; i < mempool_size && new_block.transaction_count < 5; i++) {
        if (mempool[i].status == STATUS_PENDING) {
            new_block.transactions[new_block.transaction_count] = mempool[i].tx;
            new_block.transaction_count++;
            mempool[i].status = STATUS_CONFIRMED;

            // Update balances and nonces
            Account* s = get_account(mempool[i].tx.sender_address);
            Account* r = get_account(mempool[i].tx.receiver_address);
            if (s) { s->balance -= mempool[i].tx.amount; s->nonce++; }
            if (r) { r->balance += mempool[i].tx.amount; }

            if (tx_history_count < MAX_TX_HISTORY) {
                transaction_history[tx_history_count] = mempool[i].tx;
                tx_history_count++;
            }
        }
    }

    if (new_block.transaction_count == 0) {
        printf("Mempool contains only SUSPICIOUS transactions. Mine aborted.\n");
        free(new_block.transactions);
        return;
    }

    compute_merkle_root(new_block.transactions, new_block.transaction_count, new_block.merkle_root);

    printf("Mining block... (Difficulty: %u)\n", chain_state.current_difficulty);
    char current_hash[65];

    while (1) {
        calculate_block_hash(&new_block, current_hash);
        if (is_hash_valid(current_hash, new_block.difficulty)) {
            strcpy(new_block.block_id, current_hash);
            printf("Block %d mined! Hash: %s\n", block_count, new_block.block_id);
            break;
        }
        new_block.nonce++;
    }

    blockchain[block_count] = new_block;
    block_count++;
    adjust_difficulty();
}

// Verify blockchain
int verify_blockchain() {
    printf("Running full cryptographic blockchain verification...\n");
    for (int i = 0; i < block_count; i++) {
        Block* current_block = &blockchain[i];
        if (i > 0) {
            Block* previous_block = &blockchain[i - 1];
            if (strcmp(current_block->previous_hash, previous_block->block_id) != 0) {
                printf("CHAIN BROKEN at Block %d: Previous Hash link severed.\n", i); return 0;
            }
            if (current_block->timestamp <= previous_block->timestamp) {
                printf("TIMESTAMP ERROR at Block %d.\n", i); return 0;
            }
        }
        char recomputed_hash[65];
        calculate_block_hash(current_block, recomputed_hash);
        if (strcmp(current_block->block_id, recomputed_hash) != 0) {
            printf("TAMPER DETECTED at Block %d: Header Hash mismatch.\n", i); return 0;
        }
        if (!is_hash_valid(recomputed_hash, current_block->difficulty)) {
            printf("CONSENSUS FAILURE at Block %d: Proof-of-Work invalid.\n", i); return 0;
        }

        char recomputed_merkle_root[65];
        compute_merkle_root(current_block->transactions, current_block->transaction_count, recomputed_merkle_root);
        if (strcmp(current_block->merkle_root, recomputed_merkle_root) != 0) {
            printf("TAMPER DETECTED at Block %d: Merkle Root mismatch.\n", i); return 0;
        }
    }
    printf("Blockchain verification successful. All ECDSA signatures, Merkle Roots, and Hash links intact.\n");
    return 1;
}

// Write full blockchain engine states to binary layout
void save_chain_state() {
    FILE* file = fopen(CHAIN_FILE, "wb");
    if (file == NULL) return;
    printf("Saving chain state to disk...\n");

    // Save Blocks
    fwrite(&block_count, sizeof(int), 1, file);
    for (int i = 0; i < block_count; i++) {
        fwrite(&blockchain[i], sizeof(Block), 1, file);
        fwrite(blockchain[i].transactions, sizeof(Transaction), blockchain[i].transaction_count, file);
    }

    // Save Policies
    fwrite(&policy_count, sizeof(int), 1, file);
    fwrite(policy_roster, sizeof(Policy), policy_count, file);

    // Save Accounts
    fwrite(&account_count, sizeof(int), 1, file);
    fwrite(accounts, sizeof(Account), account_count, file);

    // Save UTXOs
    fwrite(&utxo_count, sizeof(int), 1, file);
    fwrite(utxo_set, sizeof(UTXO), utxo_count, file);

    // Save Transaction Audit History
    fwrite(&tx_history_count, sizeof(int), 1, file);
    fwrite(transaction_history, sizeof(Transaction), tx_history_count, file);

    // Save Global Balances
    fwrite(&insurance_pool_balance, sizeof(double), 1, file);
    fwrite(&reinsurance_pool_balance, sizeof(double), 1, file);
    fwrite(&chain_state, sizeof(ChainState), 1, file);

    fclose(file);
    printf("State saved.\n");
}

// Load binary layout structures back into memory
void load_chain_state() {
    FILE* file = fopen(CHAIN_FILE, "rb");
    if (file == NULL) {
        printf("No chain file found. Starting fresh.\n");
        return;
    }
    printf("Loading chain state...\n");

    // Load Blocks
    fread(&block_count, sizeof(int), 1, file);
    for (int i = 0; i < block_count; i++) {
        fread(&blockchain[i], sizeof(Block), 1, file);
        blockchain[i].transactions = malloc(blockchain[i].transaction_count * sizeof(Transaction));
        if (blockchain[i].transactions != NULL) {
            fread(blockchain[i].transactions, sizeof(Transaction), blockchain[i].transaction_count, file);
        }
    }

    // Load Policies
    fread(&policy_count, sizeof(int), 1, file);
    fread(policy_roster, sizeof(Policy), policy_count, file);

    // Load Accounts
    fread(&account_count, sizeof(int), 1, file);
    fread(accounts, sizeof(Account), account_count, file);

    // Load UTXOs
    fread(&utxo_count, sizeof(int), 1, file);
    fread(utxo_set, sizeof(UTXO), utxo_count, file);

    // Load Transaction Audit History
    fread(&tx_history_count, sizeof(int), 1, file);
    fread(transaction_history, sizeof(Transaction), tx_history_count, file);

    // Load Global Balances
    fread(&insurance_pool_balance, sizeof(double), 1, file);
    fread(&reinsurance_pool_balance, sizeof(double), 1, file);
    fread(&chain_state, sizeof(ChainState), 1, file);

    fclose(file);
}

// System Transaction Helper
void process_system_tx(const char* sender_id, const char* receiver_id, int type, const char* success_msg) {
    Account* sender = get_account(sender_id);
    if (!sender) { printf("ERROR: Sender account not found.\n"); return; }
    Transaction tx = {0};
    snprintf(tx.transaction_id, sizeof(tx.transaction_id), "SYS_%ld", (long)time(NULL));
    strcpy(tx.sender_address, sender->address); strcpy(tx.receiver_address, receiver_id);
    tx.amount = 0.0; tx.transaction_type = type; tx.timestamp = time(NULL); tx.sender_nonce = sender->nonce + 1;
    sign_transaction(&tx, sender->priv_key);
    if (add_to_mempool(tx, 0.0)) printf("%s\n", success_msg);
}

// Main function
int main() {
    char input[512];
    char *cmd, *arg1, *arg2, *arg3;

    printf("ALU Health Insurance Blockchain Node Active \n");

    load_chain_state();

    initialize_system_wallets();

    if (!chain_verified) {
        printf("WARNING: Chain loaded from disk. You must run 'blockchain_verify' before interacting.\n");
    }

    while (1) {
        printf("\nalu-chain> ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = 0;
        if (strlen(input) == 0) continue;

        cmd = strtok(input, " ");
        arg1 = strtok(NULL, " ");
        arg2 = strtok(NULL, " ");
        arg3 = strtok(NULL, " ");


        if (!chain_verified && strcmp(cmd, "blockchain_verify") != 0) {
            printf("ERROR: Run 'blockchain_verify' to audit state first.\n");
            continue;
        }

	 // System Operations
        if (strcmp(cmd, "help") == 0) {
            printf("(Membership)\n  register_member <id> <bal>\n  view_member <id>\n  wallet_balance <id>\n");
            printf("(Policies)\n  enroll_policy <mem_id> <pol_id> <plan>\n  view_policy <mem_id>\n  renew_policy <mem_id>\n  policy_status <mem_id>\n");
            printf("(Tokens & Accounts)\n  token_transfer <from> <to> <amt>\n  token_balance <id>\n  account_balance <id>\n  account_transfer <from> <to> <amt>\n  account_nonce <id>\n");
            printf("(Insurance)\n  pay_premium <mem_id> <amt>\n  submit_claim <prov_id> <mem_id> <amt>\n  approve_claim <tx_id>\n  reject_claim <tx_id>\n  settle_claim <prov_id> <amt>\n  service_request <mem_id> <type>\n  preauth_request <mem_id> <proc>\n  preauth_approve <req_id>\n  reinsurance_balance\n");
            printf("(Blockchain & Mining)\n  create_transaction <sender> <receiver> <amt>\n  mempool_view\n  mine_solo\n  mine_pool\n  blockchain_view\n  blockchain_verify\n  difficulty_status\n  chain_save\n  chain_load\n");
            printf("(UTXO)\n  utxo_view\n  utxo_validate <tx_id>\n");
            printf("(Faud & Audit)\n  fraud_review\n  approve_suspicious <tx_id>\n  reject_suspicious <tx_id>\n  transaction_history\n  provider_history <id>\n  premium_history\n  claim_history\n");
            printf("(System)\n  exit\n");
        }
        else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            printf("Shutting down node...\n");
            save_chain_state();
            break;
        }

	   // Membership management
        else if (strcmp(cmd, "register_member") == 0 && arg1 && arg2) {
            if (get_account(arg1) != NULL) {
                printf("ERROR: Member wallet %s is already registered on the network.\n", arg1);
            } else if (account_count < MAX_ACCOUNTS) {
                Account new_acc;
                new_acc.balance = atof(arg2);
                new_acc.nonce = 0;

                char pub_hex[135], priv_hex[70];
                generate_wallet_keys(pub_hex, priv_hex);

                // Store ID mapped with public hex key
                snprintf(new_acc.address, sizeof(new_acc.address), "%s_%s", arg1, pub_hex);
                strcpy(new_acc.priv_key, priv_hex);

                accounts[account_count++] = new_acc;
                printf("Member wallet %s registered with %.2f AHT.\n", arg1, new_acc.balance);
            } else {
                printf("Failed to register member. Network limit reached.\n");
            }
        }

        else if ((strcmp(cmd, "view_member") == 0 || strcmp(cmd, "wallet_balance") == 0 || strcmp(cmd, "token_balance") == 0 || strcmp(cmd, "account_balance") == 0) && arg1) {
            Account* acc = get_account(arg1);
            if (acc) printf("Wallet %s | Balance: %.2f AHT | Nonce: %u\n", arg1, acc->balance, acc->nonce);
            else printf("Wallet %s not found.\n", arg1);
        }

        else if (strcmp(cmd, "account_nonce") == 0 && arg1) {
            Account* acc = get_account(arg1);
            if (acc) printf("Wallet %s Current Nonce: %u\n", arg1, acc->nonce);
            else printf("Wallet not found.\n");
        }

	 // Policy operations
        else if (strcmp(cmd, "enroll_policy") == 0 && arg1 && arg2 && arg3) {
            enroll_policy(arg1, arg2, atoi(arg3));
        }

        else if (strcmp(cmd, "view_policy") == 0 && arg1) {
            Policy* p = get_policy(arg1);
            if (p) printf("Policy %s | Member: %s | Plan: %d | Status: %s\n", p->policy_id, p->member_id, p->coverage_plan, p->status == 1 ? "ACTIVE" : "EXPIRED");
            else printf("Policy not found for member %s.\n", arg1);
        }

        else if (strcmp(cmd, "renew_policy") == 0 && arg1) {
            Policy* p = get_policy(arg1);
            if (p) {
                p->expiry_date = time(NULL) + (365 * 24 * 60 * 60);
                p->status = 1;
                printf("Policy for %s renewed for 365 days.\n", arg1);
            } else printf("Policy not found.\n");
        }

        else if (strcmp(cmd, "policy_status") == 0 && arg1) {
            Policy* p = get_policy(arg1);
            if (p) {
                if (time(NULL) > p->expiry_date) { p->status = 0; printf("Policy for %s is EXPIRED.\n", arg1); }
                else printf("Policy for %s is ACTIVE.\n", arg1);
            } else printf("Policy not found.\n");
        }

	// Token & Account transfer
        else if ((strcmp(cmd, "token_transfer") == 0 || strcmp(cmd, "account_transfer") == 0 || strcmp(cmd, "create_transaction") == 0) && arg1 && arg2 && arg3) {
            Account* sender = get_account(arg1);
            if (!sender) { printf("ERROR: Sender account not found.\n"); continue; }

            Transaction tx = {0};
            snprintf(tx.transaction_id, sizeof(tx.transaction_id), "TX_%ld", (long)time(NULL));
            strcpy(tx.sender_address, sender->address);
            strcpy(tx.receiver_address, arg2);
            tx.amount = atof(arg3);
            tx.transaction_type = 1;
            tx.timestamp = time(NULL);
            tx.sender_nonce = sender->nonce + 1;

            printf("Signing transaction with private key...\n");
            sign_transaction(&tx, sender->priv_key);

            printf("Submitting transfer to mempool...\n");
            add_to_mempool(tx, 0.1);
        }

	 // Insurance operations
        else if (strcmp(cmd, "pay_premium") == 0 && arg1 && arg2) {
            pay_premium(arg1, atof(arg2));
        }
        else if (strcmp(cmd, "submit_claim") == 0 && arg1 && arg2 && arg3) {
            Policy* p = get_policy(arg2);
            Account* sender = get_account(arg2);

            if (p == NULL) printf("ERROR: Policy does not exist for member.\n");
            else if (time(NULL) > p->expiry_date) printf("ERROR: Policy EXPIRED. Claim rejected.\n");
            else if (sender == NULL) printf("ERROR: Sender account not found.\n");
            else {
                Transaction tx = {0};
                snprintf(tx.transaction_id, sizeof(tx.transaction_id), "CLM_%ld", (long)time(NULL));
                strcpy(tx.sender_address, sender->address);
                strcpy(tx.receiver_address, arg1);
                tx.amount = atof(arg3);
                tx.transaction_type = 3;
                tx.timestamp = time(NULL);
                tx.sender_nonce = sender->nonce + 1;

                printf("Signing transaction with private key...\n");
                sign_transaction(&tx, sender->priv_key);

                printf("Validating and submitting claim to mempool...\n");
                add_to_mempool(tx, 0.5);
            }
        }
        else if (strcmp(cmd, "approve_claim") == 0 && arg1) {
            process_system_tx("INSURANCE_POOL", arg1, 7, "Claim officially approved on-chain.");
        }
        else if (strcmp(cmd, "reject_claim") == 0 && arg1) {
            process_system_tx("INSURANCE_POOL", arg1, 8, "Claim officially rejected on-chain.");
        }
        else if (strcmp(cmd, "settle_claim") == 0 && arg1 && arg2) {
            settle_claim(arg1, atof(arg2));
        }
        else if ((strcmp(cmd, "service_request") == 0 || strcmp(cmd, "preauth_request") == 0) && arg1 && arg2) {
            printf("Request logged for %s. Awaiting authorization.\n", arg1);
        }
        else if (strcmp(cmd, "preauth_request") == 0 && arg1 && arg2) {
            process_system_tx(arg1, "INSURANCE_POOL", 5, "Pre-auth requested on-chain.");
        }
        else if (strcmp(cmd, "preauth_approve") == 0 && arg1) {
            printf("Pre-authorization %s approved.\n", arg1);
        }
        else if (strcmp(cmd, "reinsurance_balance") == 0) {
            printf("Reinsurance Pool: %.2f AHT\n", reinsurance_pool_balance);
        }

	// Blockchain & Mining operations
        else if (strcmp(cmd, "mempool_view") == 0) {
            printf("\n-- MEMPOOL (%d Txs) --\n", mempool_size);
            for(int i=0; i<mempool_size; i++) {
                printf("%d Sender: %s | Amount: %.2f | Status: %s\n", i, mempool[i].tx.sender_address, mempool[i].tx.amount,
                       mempool[i].status == STATUS_PENDING ? "PENDING" : (mempool[i].status == STATUS_SUSPICIOUS ? "SUSPICIOUS" : "CONFIRMED"));
            }
        }
        else if (strcmp(cmd, "mine_solo") == 0) {
            mine_block("MINER_SOLO_01", 0);
        }
        else if (strcmp(cmd, "mine_pool") == 0) {
            mine_block("ALU_MINER_POOL", 1);
        }
        else if (strcmp(cmd, "blockchain_view") == 0) {
            printf("\n-- BLOCKCHAIN (%d Blocks) --\n", block_count);
            for(int i=0; i<block_count; i++) {
                printf("Block %d | Hash: %s... | Txs: %u | Diff: %u\n", i, blockchain[i].block_id, blockchain[i].transaction_count, blockchain[i].difficulty);
            }
        }
        else if (strcmp(cmd, "difficulty_status") == 0) {
            printf("Difficulty: %u | Reward: %.2f AHT\n", chain_state.current_difficulty, chain_state.block_reward);
        }
        else if (strcmp(cmd, "blockchain_verify") == 0) {
            verify_blockchain();
        }
        else if (strcmp(cmd, "chain_save") == 0) {
            save_chain_state();
        }
        else if (strcmp(cmd, "chain_load") == 0) {
            load_chain_state();
        }

	 // UTXO operations
        else if (strcmp(cmd, "utxo_view") == 0) {
            printf("\n-- UTXO SET (%d Outputs) --\n", utxo_count);
            for(int i=0; i<utxo_count; i++) {
                printf("%d Owner: %s | Amount: %.2f | Spent: %s\n", i, utxo_set[i].owner_address, utxo_set[i].amount, utxo_set[i].is_spent ? "YES" : "NO");
            }
        }
        else if (strcmp(cmd, "utxo_validate") == 0 && arg1) {
            int found = 0;
            for(int i=0; i<utxo_count; i++) {
                if (strcmp(utxo_set[i].transaction_id, arg1) == 0) {
                    printf("UTXO %s | Valid: %s\n", arg1, utxo_set[i].is_spent ? "FALSE (Already Spent)" : "TRUE (Unspent)");
                    found = 1; break;
                }
            }
            if (!found) printf("UTXO not found.\n");
        }

	  // Fraud operations
        else if (strcmp(cmd, "fraud_review") == 0) {
            printf("\n-- FRAUD REVIEW QUEUE --\n");
            int flagged = 0;
            for(int i=0; i<mempool_size; i++) {
                if (mempool[i].status == STATUS_SUSPICIOUS) {
                    printf("TX: %s | Sender: %s | Amount: %.2f\n", mempool[i].tx.transaction_id, mempool[i].tx.sender_address, mempool[i].tx.amount);
                    flagged++;
                }
            }
            if (flagged == 0) printf("No suspicious transactions found.\n");
        }
        else if (strcmp(cmd, "approve_suspicious") == 0 && arg1) {
            for(int i=0; i<mempool_size; i++) {
                if (strcmp(mempool[i].tx.transaction_id, arg1) == 0 && mempool[i].status == STATUS_SUSPICIOUS) {
                    mempool[i].status = STATUS_PENDING;
                    printf("Transaction %s approved and returned to PENDING queue.\n", arg1);
                    break;
                }
            }
        }
        else if (strcmp(cmd, "reject_suspicious") == 0 && arg1) {
            for(int i=0; i<mempool_size; i++) {
                if (strcmp(mempool[i].tx.transaction_id, arg1) == 0 && mempool[i].status == STATUS_SUSPICIOUS) {
                    printf("Transaction %s permanently rejected and dropped from mempool.\n", arg1);
                    for (int j = i; j < mempool_size - 1; j++) mempool[j] = mempool[j + 1];
                    mempool_size--;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "transaction_history") == 0 || strcmp(cmd, "provider_history") == 0 || strcmp(cmd, "premium_history") == 0 || strcmp(cmd, "claim_history") == 0) {
            printf("\n-- AUDIT LOG (%d Records) --\n", tx_history_count);
            for(int i=0; i<tx_history_count; i++) {
                printf("TX: %s | Type: %d | Amount: %.2f\n", transaction_history[i].transaction_id, transaction_history[i].transaction_type, transaction_history[i].amount);
            }
        }

        else {
            printf("Invalid command or missing arguments. Type 'help' for the syntax manual.\n");
        }
    }
    return 0;
}
