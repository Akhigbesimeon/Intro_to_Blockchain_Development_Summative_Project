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
