//
// Orchid Ethereum Contracts Lib
//
import {OrchidContracts} from "./orchid-eth-contracts";
import {EthAddress, ETH, GWEI, Keiki, KEIKI, OXT, Secret} from "./orchid-types";
import Web3 from "web3";
import {PromiEvent} from "web3-core";
import {OrchidAPI} from "./orchid-api";
import {EthereumTransaction, OrchidTransaction, OrchidTransactionType} from "./orchid-tx";
import "../i18n/i18n_util";
import {getParam, parseFloatSafe, removeHexPrefix} from "../util/util";
import {OrchidWeb3API} from "./orchid-eth-web3";

const BigInt = require("big-integer"); // Mobile Safari requires polyfill
const ORCHID_SIGNER_KEYS_WALLET = "orchid-signer-keys";

declare global {
  interface Window {
    ethereum: any
  }
}
// TODO: Use the Wei and Keiki types here
/// A Funder address containing ETH to perform contract transactions  and possibly
/// OXT to fund a Lottery Pot.
export class Wallet {
  public address: EthAddress;
  public ethBalance: BigInt; // Wei
  public oxtBalance: BigInt; // Keiki (1e18 per OXT)

  constructor() {
    this.address = "";
    this.ethBalance = BigInt(0);
    this.oxtBalance = BigInt(0);
  }
}

/// A Wallet may have many signers, each of which is essentially an "Orchid Account",
// controlling a Lottery Pot.
export class Signer {
  // The wallet with which this signer is associated.
  public wallet: Wallet;
  // The signer public address.
  public address: EthAddress;
  // The signer private key, if available.
  public secret: Secret | undefined;

  constructor(wallet: Wallet, address: EthAddress, secret?: Secret) {
    this.wallet = wallet;
    this.address = address;
    this.secret = removeHexPrefix(secret);
  }

  toConfigString(): string | undefined {
    if (this.secret === undefined) {
      return undefined;
    }
    return `account={protocol:"orchid",funder:"${this.wallet.address}",secret:"${this.secret}"}`;
  }
}

interface EthereumKey {
  address: string
  privateKey: string
}

export type Web3Wallet = any;

/// A Lottery Pot containing OXT funds against which lottery tickets are issued.
export class LotteryPot {
  public signer: Signer;
  public balance: KEIKI;
  public escrow: KEIKI; // TODO: rename deposit
  public unlock: Date | null;

  constructor(signer: Signer, balance: BigInt, escrow: BigInt, unlock: Date | null) {
    this.signer = signer;
    this.signer = signer;
    this.balance = balance;
    this.escrow = escrow;
    this.unlock = unlock;
  }

  isLocked(): boolean {
    return this.unlock == null || new Date() < this.unlock;
  }

  isUnlocked(): boolean {
    return !this.isLocked();
  }

  isUnlocking(): boolean {
    return this.unlock != null && new Date() < this.unlock;
  }
}

export class OrchidEthereumAPI {

  provider: OrchidWeb3API = new OrchidWeb3API()

  get web3(): Web3 {
    if (this.provider.web3) {
      return this.provider.web3
    }
    throw Error("Provider web3 unavailable.");
  }

  /// Get the user's ETH wallet balance and Keiki token balance (1e18 per OXT).
  async orchidGetWallet(): Promise<Wallet> {
    const accounts = await this.web3.eth.getAccounts();
    if (accounts.length === 0) {
      throw Error("no accounts");
    }
    const wallet = new Wallet();
    wallet.address = accounts[0];
    try {
      wallet.ethBalance = BigInt(await this.web3.eth.getBalance(accounts[0]));
    } catch (err) {
      console.log("Error getting eth balance", err);
      throw err;
    }
    try {
      let overrideBalanceOXT: number | null = parseFloatSafe(getParam("walletBalanceOxt"));
      let overrideBalance: BigInt | null = overrideBalanceOXT ? new OXT(overrideBalanceOXT).toKeiki() : null
      wallet.oxtBalance = overrideBalance || BigInt(await OrchidContracts.token.methods.balanceOf(accounts[0]).call());
    } catch (err) {
      console.log("Error getting oxt balance", err);
      throw err;
    }
    return wallet;
  }

  async orchidGetSigners(wallet: Wallet): Promise<Signer []> {
    if (getParam("no_signers")) {
      return [];
    }
    let signerAddresses;
    try {
      signerAddresses = await OrchidContracts.lottery.methods.keys(wallet.address).call();
    } catch (err) {
      console.log("Error getting signers list", err);
      throw err;
    }
    console.log("orchidGetSigners: orchid signers: ", signerAddresses);

    // Add the signer keys for any signers created in this wallet.
    let signerKeys = this.orchidGetSignerKeys() as EthereumKey [];
    return signerAddresses.map((address: EthAddress) => {
      let found = Array.from(signerKeys).find(key => key.address === address);
      let secret = found === undefined ? undefined : found.privateKey;
      return new Signer(wallet, address, secret);
    });
  }

  /// Get the Orchid signer keys wallet in local storage.
  orchidGetSignerKeys(): Web3Wallet {
    let keys = this.web3.eth.accounts.wallet.load("", ORCHID_SIGNER_KEYS_WALLET);
    return keys;
  }

  /// Create a new signer keypair and save it in the Orchid signer keys wallet in local storage.
  orchidCreateSigner(wallet: Wallet): Signer {
    let signersWallet = this.orchidGetSignerKeys();
    let signerAccount = this.web3.eth.accounts.create();
    signersWallet.add(signerAccount);
    signersWallet.save("", ORCHID_SIGNER_KEYS_WALLET);
    return new Signer(wallet, signerAccount.address, signerAccount.privateKey);
  }

  // TODO: Use Keiki type here
  /// Transfer the amount in Keiki (1e18 per OXT) from the user to the specified lottery pot address.
  /// If the total exceeds walletBalance the amount value is automatically reduced.
  async orchidAddFunds(
    funder: EthAddress, signer: EthAddress, amount: BigInt, escrow: BigInt, walletBalance: KEIKI, gasPrice?: number
  ): Promise<string> {
    //return fakeTx(false);
    const amount_value = BigInt(amount); // Force our polyfill BigInt?
    const escrow_value = BigInt(escrow);

    // Don't attempt to add more than the wallet balance.
    // This mitigates the potential for rounding errors in calculated amounts.
    const total = BigInt.min(amount_value.add(escrow_value), walletBalance);
    console.log("Add funds  signer: ", signer, " amount: ", (total.minus(escrow_value)), " escrow: ", escrow);

    async function doApproveTx() {
      return new Promise<string>(function (resolve, reject) {
        OrchidContracts.token.methods.approve(
          OrchidContracts.lottery_addr(),
          total.toString()
        ).send({
          from: funder,
          gas: OrchidContracts.token_approval_max_gas,
          gasPrice: gasPrice
        })
          .on("transactionHash", (hash: any) => {
            console.log("Approval hash: ", hash);
            resolve(hash);
          })
          .on('confirmation', (confirmationNumber: any, receipt: any) => {
            console.log("Approval confirmation ", confirmationNumber, JSON.stringify(receipt));
          })
          .on('error', (err: any) => {
            console.log("Approval error: ", JSON.stringify(err));
            // If there is an error in the approval assume Funding will fail.
            reject(err['message']);
          });
      });
    }

    async function doFundTx(approvalHash: string) {
      return new Promise<string>(function (resolve, reject) {
        OrchidContracts.lottery.methods.push(
          signer,
          total.toString(),
          escrow_value.toString()
        ).send({
          from: funder,
          gas: OrchidContracts.lottery_push_max_gas,
          gasPrice: gasPrice
        })
          .on("transactionHash", (hash: any) => {
            console.log("Fund hash: ", hash);
            OrchidAPI.shared().transactionMonitor.add(
              new OrchidTransaction(new Date(), OrchidTransactionType.AddFunds, [approvalHash, hash]));
          })
          .on('confirmation', (confirmationNumber: any, receipt: any) => {
            console.log("Fund confirmation", confirmationNumber, JSON.stringify(receipt));
            // Wait for confirmations on the funding tx.
            if (confirmationNumber >= EthereumTransaction.requiredConfirmations()) {
              const hash = receipt['transactionHash'];
              resolve(hash);
            } else {
              console.log("waiting for more confirmations...");
            }
          })
          .on('error', (err: any) => {
            console.log("Fund error: ", JSON.stringify(err));
            reject(err['message']);
          });
      });
    }

    // The approval tx resolves immediately after the user submits.
    let approvalHash = await doApproveTx();

    // Introduce a short artificial delay before issuing the second tx
    // Issue: We have had reports of problems where only one dialog is presented to the user.
    // Issue: Trying this to see if it mitigates any race conditions in the wallet.
    await new Promise(r => setTimeout(r, 1000));

    // The UI monitors the funding tx.
    return doFundTx(approvalHash);
  }

  /// Transfer the amount in Keiki (1e18 per OXT) from the user to the specified directory address.
  /// Amount won't exceed walletBalance.
  async orchidStakeFunds(
    funder: EthAddress, stakee: EthAddress, amount: BigInt, walletBalance: KEIKI, delay: BigInt, gasPrice?: number
  ): Promise<string> {
    const amount_value = BigInt.min(amount, walletBalance);
    const delay_value = BigInt(delay);
    console.log("Stake funds amount: ", amount);

    async function doApproveTx() {
      return new Promise<string>(function (resolve, reject) {
        OrchidContracts.token.methods.approve(
          OrchidContracts.directory_addr(),
          amount_value.toString()
        ).send({
          from: funder,
          gas: OrchidContracts.token_approval_max_gas,
          gasPrice: gasPrice
        })
          .on("transactionHash", (hash: any) => {
            console.log("Approval hash: ", hash);
            resolve(hash);
          })
          .on('confirmation', (confirmationNumber: any, receipt: any) => {
            console.log("Approval confirmation ", confirmationNumber, JSON.stringify(receipt));
          })
          .on('error', (err: any) => {
            console.log("Approval error: ", JSON.stringify(err));
            // If there is an error in the approval assume Funding will fail.
            reject(err['message']);
          });
      });
    }

    async function doFundTx(approvalHash: string) {
      return new Promise<string>(function (resolve, reject) {
        OrchidContracts.directory.methods.push(
          stakee, amount_value.toString(), delay_value.toString()
        ).send({
          from: funder,
          gas: OrchidContracts.directory_push_max_gas,
          gasPrice: gasPrice
        })
          .on("transactionHash", (hash: any) => {
            console.log("Stake hash: ", hash);
            OrchidAPI.shared().transactionMonitor.add(
              new OrchidTransaction(new Date(), OrchidTransactionType.StakeFunds, [approvalHash, hash]));
          })
          .on('confirmation', (confirmationNumber: any, receipt: any) => {
            console.log("Stake confirmation", confirmationNumber, JSON.stringify(receipt));
            // Wait for confirmations on the funding tx.
            if (confirmationNumber >= EthereumTransaction.requiredConfirmations()) {
              const hash = receipt['transactionHash'];
              resolve(hash);
            } else {
              console.log("waiting for more confirmations...");
            }
          })
          .on('error', (err: any) => {
            console.log("Stake error: ", JSON.stringify(err));
            reject(err['message']);
          });
      });
    }

    // The approval tx resolves immediately after the user submits.
    let approvalHash = await doApproveTx();

    // Introduce a short artificial delay before issuing the second tx
    // Issue: We have had reports of problems where only one dialog is presented to the user.
    // Issue: Trying this to see if it mitigates any race conditions in the wallet.
    await new Promise(r => setTimeout(r, 1000));

    // The UI monitors the funding tx.
    return doFundTx(approvalHash);
  }

  async orchidGetStake(stakee: EthAddress): Promise<BigInt> {
    console.log("orchid get stake");
    let stake = await OrchidContracts.directory.methods.heft(stakee).call();
    return stake || BigInt(0);
  }

  /// Evaluate an Orchid method call, returning the confirmation transaction has or error.
  private evalOrchidTx<T>(promise: PromiEvent<T>, type: OrchidTransactionType): Promise<string> {
    return new Promise<string>(function (resolve, reject) {
      promise
        .on("transactionHash", (hash) => {
          console.log("hash: ", hash);
          if (type) {
            OrchidAPI.shared().transactionMonitor.add(
              new OrchidTransaction(new Date(), type, [hash]));
          }
        })
        .on('confirmation', (confirmationNumber, receipt) => {
          console.log("confirmation", confirmationNumber, JSON.stringify(receipt));
          // Wait for one confirmation on the tx.
          const hash = receipt['transactionHash'];
          resolve(hash);
        })
        .on('error', (err) => {
          console.log("error: ", JSON.stringify(err));
          reject(err['message']);
        });
    });
  }

  /// Move `amount` from balance to escrow, not exceeding `potBalance`.
  async orchidMoveFundsToEscrow(
    funder: EthAddress, signer: EthAddress, amount: BigInt, potBalance: BigInt
  ): Promise<string> {
    console.log(`moveFunds amount: ${amount.toString()}`);

    // Don't take more than the pot balance. This check mitigates rounding errors.
    amount = BigInt.min(amount, potBalance);

    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.move(signer, amount.toString()).send({
        from: funder,
        gas: OrchidContracts.lottery_move_max_gas,
      }), OrchidTransactionType.MoveFundsToEscrow
    );
  }

  /// Withdraw `amount` from the lottery pot to the specified eth address, not exceeding `potBalance`.
  async orchidWithdrawFunds(
    funder: EthAddress, signer: EthAddress, targetAddress: EthAddress, amount: BigInt, potBalance: BigInt
  ): Promise<string> {
    // pull(address signer, address payable target, bool autolock, uint128 amount, uint128 escrow) external {
    let autolock = true;
    let escrow = BigInt(0);

    // Don't take more than the pot balance. This check mitigates rounding errors.
    amount = BigInt.min(amount, potBalance);
    console.log(`withdrawFunds to: ${targetAddress} amount: ${amount}`);

    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.pull(signer, targetAddress, autolock, amount.toString(), escrow.toString()).send({
        from: funder,
        gas: OrchidContracts.lottery_pull_amount_max_gas,
      }), OrchidTransactionType.WithdrawFunds
    );
  }

  /// Pull all funds and escrow, subject to lock time.
  async orchidWithdrawFundsAndEscrow(funder: EthAddress, signer: EthAddress, targetAddress: EthAddress): Promise<string> {
    console.log("withdrawFundsAndEscrow");
    let autolock = true;
    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.yank(signer, targetAddress, autolock).send({
        from: funder,
        gas: OrchidContracts.lottery_pull_all_max_gas
      }), OrchidTransactionType.WithdrawFunds
    );
  }

  /// Clear the unlock / warn time period.
  async orchidLock(funder: EthAddress, signer: EthAddress): Promise<string> {
    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.lock(signer).send({
        from: funder,
        gas: OrchidContracts.lottery_lock_max_gas
      }), OrchidTransactionType.Lock
    );
  }

  /// Start the unlock / warn time period (one day in the future).
  async orchidUnlock(funder: EthAddress, signer: EthAddress): Promise<string> {
    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.warn(signer).send({
        from: funder,
        gas: OrchidContracts.lottery_warn_max_gas
      }), OrchidTransactionType.Unlock
    );
  }

  /// Get the lottery pot balance and escrow amount for the specified address.
  async orchidGetLotteryPot(funder: Wallet, signer: Signer): Promise<LotteryPot> {
    // Allow overrides
    let overrideBalanceOXT: number | null = parseFloatSafe(getParam("balance"));
    let overrideEscrowOXT: number | null = parseFloatSafe(getParam("deposit"));
    let overrideBalance: BigInt | null = overrideBalanceOXT ? new OXT(overrideBalanceOXT).toKeiki() : null
    let overrideEscrow: BigInt | null = overrideEscrowOXT ? new OXT(overrideEscrowOXT).toKeiki() : null

    //console.log("get lottery pot for signer: ", signer);
    let result = await OrchidContracts.lottery.methods
      .look(funder.address, signer.address)
      .call({from: funder.address});
    if (result == null || result._length < 3) {
      console.log("get lottery pot failed");
      throw new Error("Unable to get lottery pot");
    }
    const balance: BigInt = overrideBalance || result[0];
    const escrow: BigInt = overrideEscrow || result[1];
    const unlock: number = Number(result[2]);
    const unlockDate: Date | null = unlock > 0 ? new Date(unlock * 1000) : null;
    //console.log("Pot info: ", balance, "escrow: ", escrow, "unlock: ", unlock, "unlock date:", unlockDate);
    return new LotteryPot(signer, balance, escrow, unlockDate);
  }

  // Exercise the reset account feature of the lotter_test_reset contract.
  async orchidReset(funder: Wallet): Promise<string> {
    return this.evalOrchidTx(
      OrchidContracts.lottery.methods.reset(funder.address)
        .send({
          from: funder.address,
          gas: OrchidContracts.lottery_move_max_gas,
        }), OrchidTransactionType.Reset
    );
  }

  // The current median gas price for the past few blocks
  async getGasPrice(): Promise<GWEI> {
    try {
      return GWEI.fromWeiString(await this.web3.eth.getGasPrice())
    } catch (err) {
      console.log("WARNING: defaulting gas price in disconnected state.  Testing only!")
      return new GWEI(50);
    }
  }
}

export class GasPricingStrategy {

  // TODO: Have this return GWEI
  /// Choose a gas price taking into account current gas price and the wallet balance.
  /// This strategy uses a multiple of the current median gas price up to a hard limit on
  /// both gas price and fraction of the wallet's remaiing ETH balance.
  // Note: Some of the usage of BigInt in here is convoluted due to the need to import the polyfill.
  static chooseGasPrice(
    targetGasAmount: number, currentMedianGasPrice: GWEI, currentEthBalance: BigInt): number | undefined {
    let maxPriceGwei = 200.0;
    let minPriceGwei = 5.0;
    let medianMultiplier = 1.2;
    let maxWalletFrac = 1.0;

    // Target our multiple of the median price
    let targetPrice: BigInt = currentMedianGasPrice.multiply(medianMultiplier).toWei();

    // Don't exceed max price
    let maxPrice: BigInt = BigInt(maxPriceGwei).multiply(1e9);
    if (maxPrice < targetPrice) {
      console.log("Gas price calculation: limited by max price to : ", maxPriceGwei)
    }
    targetPrice = BigInt.min(targetPrice, maxPrice);

    // Don't fall below min price
    let minPrice: BigInt = BigInt(minPriceGwei).multiply(1e9);
    if (minPrice > targetPrice) {
      console.log("Gas price calculation: limited by min price to : ", minPriceGwei)
    }
    targetPrice = BigInt.max(targetPrice, minPrice);

    // Don't exceed max wallet fraction
    let targetSpend: BigInt = BigInt(targetPrice).multiply(targetGasAmount);
    let maxSpend = BigInt(Math.floor(BigInt(currentEthBalance) * maxWalletFrac));
    if (targetSpend > maxSpend) {
      console.log("Gas price calculation: limited by wallet balance: ", currentEthBalance)
    }
    targetSpend = BigInt.min(targetSpend, maxSpend);

    // Recalculate the price
    let price = BigInt(targetSpend).divide(targetGasAmount);

    console.log(`Gas price calculation, `
      + `targetGasAmount: ${targetGasAmount}, medianGasPrice: ${currentMedianGasPrice.value}, ethBalance: ${currentEthBalance}, chose price: ${BigInt(price).divide(1e9)}`
    );

    return price.toJSNumber();
  }
}

// TODO:
export function isEthAddress(str: string): boolean {
  return Web3.utils.isAddress(str)
}

/// Convert a keiki value to an OXT String rounded to the specified
/// number of decimal places.
export function keikiToOxtString(keiki: BigInt | null, decimals: number = 2, ifNull: string = "...") {
  if (keiki === null) {
    return ifNull
  }
  decimals = Math.round(decimals);
  let val: number = new Keiki(keiki).toOXT().value;
  return val.toFixedLocalized(decimals);
}

export function weiToETHString(wei: BigInt | null, decimals: number = 2, ifNull: string = "...") {
  if (wei === null) {
    return ifNull
  }
  decimals = Math.round(decimals);
  let val: number = ETH.fromWei(wei).value;
  return val.toFixedLocalized(decimals);
}

// @deprecated - use OXT instance methods
export function oxtToKeiki(oxt: number): KEIKI {
  return new OXT(oxt).toKeiki();
}


