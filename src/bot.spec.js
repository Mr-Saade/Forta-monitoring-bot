const {
  Finding,
  FindingSeverity,
  FindingType,
  createTransactionEvent,
} = require("forta-agent");
const agent = require("./bot");

describe("flash loan monitoring bot", () => {
  let handleTransaction;
  const mockEthersProvider = {
    getBalance: jest.fn(),
  };
  const mockGetTransactionReceipt = jest.fn();

  const createTxEvent = ({addresses, logs, blockNumber}) =>
    createTransactionEvent({
      transaction: {},
      logs,
      contractAddress: null,
      block: {number: blockNumber},
      addresses,
    });

  beforeAll(() => {
    handleTransaction = agent.provideHandleTransaction(
      mockEthersProvider,
      mockGetTransactionReceipt
    );
  });

  describe("handleTransaction", () => {
    it("returns empty findings if Aave V2 is not involved", async () => {
      const txEvent = createTxEvent({addresses: {}});

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns a finding if a flash loan attack is detected", async () => {
      const flashLoanTopic =
        "0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac";
      const flashLoanEvent = {
        topics: [flashLoanTopic],
      };
      const protocolAddress = "0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36";
      const blockNumber = 100;

      // Mock high gas usage
      mockGetTransactionReceipt.mockReturnValueOnce({gasUsed: "7000001"});

      const txEvent = createTxEvent({
        addresses: {
          "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": true, // Aave V2
          [protocolAddress]: true,
        },
        blockNumber,
      });

      txEvent.filterLog = jest.fn().mockReturnValue([flashLoanEvent]);

      // Mock balance changes
      const currentBalance = "1";
      const previousBalance = "200000000000000000001";
      const balanceDiff = "200000000000000000000";
      mockEthersProvider.getBalance.mockReturnValueOnce(currentBalance);
      mockEthersProvider.getBalance.mockReturnValueOnce(previousBalance);

      const findings = await handleTransaction(txEvent);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Flash Loan with Loss",
          description: `Flash Loan with loss of ${balanceDiff} detected for ${protocolAddress}`,
          alertId: "FORTA-5",
          protocol: "aave",
          type: FindingType.Suspicious,
          severity: FindingSeverity.High,
          metadata: {
            protocolAddress,
            balanceDiff,
            loans: JSON.stringify([flashLoanEvent]),
          },
        }),
      ]);
    });
  });
});
