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
