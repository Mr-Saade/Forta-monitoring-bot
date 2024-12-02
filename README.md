# Flash Loan Monitoring Bot

This project implements a Forta monitoring bot to detect suspicious flash loan transactions on the Ethereum blockchain, particularly focusing on interactions with Aave V2 and Uniswap V3 protocols. It identifies transactions that involve high gas usage and significant balance changes in monitored protocols, which could signal a potential flashloan attack or exploit.

## Features

1. **Monitors Aave V2 for Flash Loans**:

   - The bot listens for flash loan events emitted by Aave V2's smart contract.

2. **Monitored Protocols**:

   - The bot focuses on Uniswap V3's contract.
   - It tracks balance changes for this protocol during flash loan transactions.

3. **Detection Criteria**:

   - **High Gas Usage**: Transactions with gas usage greater than `5000000`.
   - **Significant Balance Change**: Balance reduction of at least 200 ETH (`200000000000000000000` Wei).

4. **Findings and Alerts**:
   - Generates findings if a suspicious flash loan transaction is detected.
   - Findings include detailed metadata such as the protocol address, balance difference, and details of the flash loan event.
