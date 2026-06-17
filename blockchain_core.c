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
