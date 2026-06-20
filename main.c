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
