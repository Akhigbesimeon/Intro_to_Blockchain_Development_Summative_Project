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
