const BigNumber = require("bignumber.js");
const {
  Finding,
  getEthersProvider,
  FindingSeverity,
  FindingType,
} = require("forta-agent");

const HIGH_GAS_THRESHOLD = "5000000";
const AAVE_V2_ADDRESS = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9";
const FLASH_LOAN_EVENT =
  "event FlashLoan(address indexed target, address indexed initiator, address indexed asset, uint256 amount, uint256 premium, uint16 referralCode)";
const MONITORED_PROTOCOLS = ["0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36"]; // Uniswap V3
const BALANCE_DIFF_THRESHOLD = "200000000000000000000"; // 200 ETH

const ethersProvider = getEthersProvider();

function provideHandleTransaction(ethersProvider, getTransactionReceipt) {
  return async function handleTransaction(txEvent) {
    const findings = [];

    // Skip if the transaction does not involve Aave V2
    if (!txEvent.addresses[AAVE_V2_ADDRESS]) return findings;

    // Look for flash loan events in the transaction logs
    const flashLoanEvents = txEvent.filterLog(FLASH_LOAN_EVENT);
    if (!flashLoanEvents.length) return findings;

    // Check if the transaction involves a monitored protocol
    const protocolAddress = MONITORED_PROTOCOLS.find(
      (address) => txEvent.addresses[address]
    );
    if (!protocolAddress) return findings;

    // Check the gas usage of the transaction
    const {gasUsed} = await getTransactionReceipt(txEvent.hash);
    if (new BigNumber(gasUsed).isLessThan(HIGH_GAS_THRESHOLD)) return findings;

    // Check the balance difference of the monitored protocol
    const blockNumber = txEvent.blockNumber;
    const currentBalance = new BigNumber(
      (await ethersProvider.getBalance(protocolAddress, blockNumber)).toString()
    );
    const previousBalance = new BigNumber(
      (
        await ethersProvider.getBalance(protocolAddress, blockNumber - 1)
      ).toString()
    );
    const balanceDiff = previousBalance.minus(currentBalance);
    if (balanceDiff.isLessThan(BALANCE_DIFF_THRESHOLD)) return findings;

    // Create a finding for the detected suspicious flash loan
    findings.push(
      Finding.fromObject({
        name: "Flash Loan with Loss",
        description: `Flash Loan with loss of ${balanceDiff.toString()} detected for ${protocolAddress}`,
        alertId: "FORTA-5",
        protocol: "aave",
        type: FindingType.Suspicious,
        severity: FindingSeverity.High,
        metadata: {
          protocolAddress,
          balanceDiff: balanceDiff.toString(),
          loans: JSON.stringify(flashLoanEvents),
        },
      })
    );

    return findings;
  };
}

module.exports = {
  provideHandleTransaction,
};
