import { ExtensionTypes, RequestLogicTypes } from '@requestnetwork/types';
import * as Types from '../../../types';
import DefaultBitcoinDetectionProvider from './default-bitcoin-detection-provider';
const bigNumber: any = require('bn.js');

/**
 * Handle payment networks with BTC based address extension
 */
export default class PaymentNetworkBTCAddressBased {
  private extension: ExtensionTypes.PnAddressBased.IAddressBased;
  private bitcoinDetectionProvider: Types.IBitcoinDetectionProvider;

  /**
   * @param extension The advanced logic payment network extensions
   */
  public constructor(
    extension: ExtensionTypes.PnAddressBased.IAddressBased,
    bitcoinDetectionProvider?: Types.IBitcoinDetectionProvider,
  ) {
    this.extension = extension;
    this.bitcoinDetectionProvider =
      bitcoinDetectionProvider || new DefaultBitcoinDetectionProvider();
  }

  /**
   * Creates the extensions data for the creation of this extension
   *
   * @param paymentNetworkCreationParameters Parameters to create the extension
   * @returns The extensionData object
   */
  public createExtensionsDataForCreation(
    paymentNetworkCreationParameters: ExtensionTypes.PnAddressBased.ICreationParameters,
  ): ExtensionTypes.IAction {
    return this.extension.createCreationAction({
      paymentAddress: paymentNetworkCreationParameters.paymentAddress,
      refundAddress: paymentNetworkCreationParameters.refundAddress,
    });
  }

  /**
   * Creates the extensions data to add payment address
   *
   * @param Parameters to add payment information
   * @returns The extensionData object
   */
  public createExtensionsDataForAddPaymentInformation(
    parameters: ExtensionTypes.PnAddressBased.IAddPaymentAddressParameters,
  ): ExtensionTypes.IAction {
    return this.extension.createAddPaymentAddressAction({
      paymentAddress: parameters.paymentAddress,
    });
  }

  /**
   * Creates the extensions data to add refund address
   *
   * @param Parameters to add refund information
   * @returns The extensionData object
   */
  public createExtensionsDataForAddRefundInformation(
    parameters: ExtensionTypes.PnAddressBased.IAddRefundAddressParameters,
  ): ExtensionTypes.IAction {
    return this.extension.createAddRefundAddressAction({
      refundAddress: parameters.refundAddress,
    });
  }

  /**
   * Gets the balance and the payment/refund events
   *
   * @param request the request to check
   * @param paymentNetworkId payment network id
   * @param networkId bitcoin network id
   * @returns the balance and the payment/refund events
   */
  public async getBalance(
    request: RequestLogicTypes.IRequest,
    paymentNetworkId: ExtensionTypes.ID,
    networkId: number,
  ): Promise<Types.IBalanceWithEvents> {
    if (!request.extensions[paymentNetworkId]) {
      throw new Error(`The request do not have the extension : ̀${paymentNetworkId}`);
    }
    const paymentAddress = request.extensions[paymentNetworkId].values.paymentAddress;
    const refundAddress = request.extensions[paymentNetworkId].values.refundAddress;

    let payments: Types.IBalanceWithEvents = { balance: '0', events: [] };
    if (paymentAddress) {
      payments = await this.extractBalanceAndEvents(
        paymentAddress,
        Types.EVENTS_NAMES.PAYMENT,
        networkId,
      );
    }

    let refunds: Types.IBalanceWithEvents = { balance: '0', events: [] };
    if (refundAddress) {
      refunds = await this.extractBalanceAndEvents(
        refundAddress,
        Types.EVENTS_NAMES.REFUND,
        networkId,
      );
    }

    const balance: string = new bigNumber(new bigNumber(payments.balance || 0))
      .sub(new bigNumber(refunds.balance || 0))
      .toString();

    const events: Types.IPaymentNetworkEvent[] = [...payments.events, ...refunds.events].sort(
      (a: Types.IPaymentNetworkEvent, b: Types.IPaymentNetworkEvent) =>
        a.parameters.timestamp - b.parameters.timestamp,
    );

    return {
      balance,
      events,
    };
  }

  /**
   * Extracts the balance and events of an address
   *
   * @private
   * @param address Address to check
   * @param eventName Indicate if it is an address for payment or refund
   * @returns The balance
   */
  private async extractBalanceAndEvents(
    address: string,
    eventName: Types.EVENTS_NAMES,
    networkId: number,
  ): Promise<Types.IBalanceWithEvents> {
    return this.bitcoinDetectionProvider.getAddressBalanceWithEvents(networkId, address, eventName);
  }
}
