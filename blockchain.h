#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

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
extern MempoolEntry mempool[MAX_MEMPOOL_SIZE];
extern int mempool_size;

extern Account accounts[MAX_ACCOUNTS];
extern int account_count;

extern UTXO utxo_set[MAX_UTXOS];
extern int utxo_count;

extern Transaction transaction_history[MAX_TX_HISTORY];
extern int tx_history_count;

extern Block blockchain[MAX_BLOCKS];
extern int block_count;

extern Policy policy_roster[MAX_ACCOUNTS];
extern int policy_count;

extern double reinsurance_pool_balance;
extern double insurance_pool_balance;
extern int chain_verified;

extern Token aht_token;
extern ChainState chain_state;

// Forward Declarations
void generate_wallet_keys(char* pub_hex, char* priv_hex);
Account* get_account(const char* address);
void sign_transaction(Transaction *tx, const char *priv_hex);
void initialize_system_wallets();
void calculate_sha256(const char* input, char* output_hash);
void get_transaction_leaf_hash(Transaction* tx, char* leaf_hash);
int verify_ecdsa_signature(Transaction* tx, const char* pub_hex);
void compute_merkle_root(Transaction* transactions, int tx_count, char* merkle_root);
void calculate_block_hash(Block* block, char* output_hash);
int is_hash_valid(const char* hash, uint32_t difficulty);
void create_utxo(const char* tx_id, const char* owner, double amount);
int consume_utxos_for_amount(const char* owner, double required_amount);
Policy* get_policy(const char* member_id);
void enroll_policy(const char* member_id, const char* policy_id, int plan);
void pay_premium(const char* member_id, double amount);
void settle_claim(const char* provider_id, double approved_amount);
int compare_mempool_entries(const void* a, const void* b);
int add_to_mempool(Transaction tx, double fee);
void adjust_difficulty();
void mine_block(const char* miner_id, int is_pool);
int verify_blockchain();
void save_chain_state();
void load_chain_state();
void process_system_tx(const char* sender_id, const char* receiver_id, int type, const char* success_msg);

#endif
