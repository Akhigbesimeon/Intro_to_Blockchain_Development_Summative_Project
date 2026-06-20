#include "blockchain.h"

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
