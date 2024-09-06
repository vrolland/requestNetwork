// import { providers, Wallet } from 'ethers';
// const circomlibjs = require('circomlibjs');

import { EthereumPrivateKeyDecryptionProvider } from '@requestnetwork/epk-decryption';
import { EthereumPrivateKeySignatureProvider } from '@requestnetwork/epk-signature';
import * as RequestNetwork from '@requestnetwork/request-client.js';

// import * as RequestPaymentProcessor from '@requestnetwork/payment-processor';

// payee information

const payeeSignatureInfo = {
  method: RequestNetwork.Types.Signature.METHOD.EDDSA_POSEIDON,
  privateKey: '0001020304050607080900010203040506070809000102030405060708090001',
};
const payeeIdentity = {
  type: RequestNetwork.Types.Identity.TYPE.POSEIDON_ADDRESS,
  value: '11e4f0cc5af0337d70fe7a9452065ceda2841d4545ffcc2b1bbefe09a1f878f0',
};

// payer information

const payerSignatureInfo = {
  method: RequestNetwork.Types.Signature.METHOD.EDDSA_POSEIDON,
  privateKey: '0000000304050607080900010203040506070809000102030405060708090001',
};
const payerIdentity = {
  type: RequestNetwork.Types.Identity.TYPE.POSEIDON_ADDRESS,
  value: '11500709bd9c9ad99cc665719bb2ca955744dd713f957a4c34a66e16cf037d93',
};

const payeeEncryptionParameters: RequestNetwork.Types.Encryption.IEncryptionParameters = {
  key:
    '9008306d319755055226827c22f4b95552c799bae7af0e99780cf1b5500d9d1ecbdbcf6f27cdecc72c97fef3703c54b717bca613894212e0b2525cbb2d1161b9',
  method: RequestNetwork.Types.Encryption.METHOD.ECIES,
};
const payeeDecryptionParameters: RequestNetwork.Types.Encryption.IDecryptionParameters = {
  key: '0x0906ff14227cead2b25811514302d57706e7d5013fcc40eca5985b216baeb998',
  method: RequestNetwork.Types.Encryption.METHOD.ECIES,
};

const payerEncryptionParameters: RequestNetwork.Types.Encryption.IEncryptionParameters = {
  key:
    'cf4a1d0bbef8bf0e3fa479a9def565af1b22ea6266294061bfb430701b54a83699e3d47bf52e9f0224dcc29a02721810f1f624f1f70ea3cc5f1fb752cfed379d',
  method: RequestNetwork.Types.Encryption.METHOD.ECIES,
};

// A decryption provider, for example @requestnetwork/epk-decryption
const decryptionProvider: RequestNetwork.Types.DecryptionProvider.IDecryptionProvider = new EthereumPrivateKeyDecryptionProvider(
  payeeDecryptionParameters,
);

// Signature providers
const signatureProvider = new EthereumPrivateKeySignatureProvider();

const requestInfo: RequestNetwork.Types.IRequestInfo = {
  currency: {
    type: RequestNetwork.Types.RequestLogic.CURRENCY.ERC20,
    value: '0x9FBDa871d559710256a2502A2517b794B482Db40',
    network: 'private',
  },
  expectedAmount: '1000000000000000000',
  payee: payeeIdentity,
  payer: payerIdentity,
};

const paymentNetwork: RequestNetwork.Types.Payment.PaymentNetworkCreateParameters = {
  id: RequestNetwork.Types.Extension.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT,
  parameters: {
    paymentAddress: '0x627306090abaB3A6e1400e9345bC60c78a8BEf57',
    feeAmount: '90000000000000000',
    feeAddress: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    refundAddress: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  },
};

/* eslint-disable @typescript-eslint/no-floating-promises */
const requestNetwork = new RequestNetwork.RequestNetwork({
  signatureProvider,
  useMockStorage: true,
  decryptionProvider,
});

/* eslint-disable no-console */

const createParams: RequestNetwork.Types.ICreateRequestParameters = {
  paymentNetwork,
  requestInfo,
  signer: payeeIdentity,
};

(async () => {
  //   const mnemonic = 'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat';
  //   const provider = new providers.JsonRpcProvider('http://localhost:8545');
  //   const wallet = Wallet.fromMnemonic(mnemonic).connect(provider);

  const payeeIDreturn = signatureProvider.addSignatureParameters(payeeSignatureInfo);
  const payerIDreturn = signatureProvider.addSignatureParameters(payerSignatureInfo);

  console.log('payeeIDreturn');
  console.log(payeeIDreturn);
  console.log(payeeIdentity);

  console.log('payerIDreturn');
  console.log(payerIDreturn);
  console.log(payerIdentity);

  createParams.requestInfo.timestamp = RequestNetwork.Utils.getCurrentTimestampInSecond();
  console.log('######################################');
  const request1 = await requestNetwork._createEncryptedRequest(createParams, [
    payeeEncryptionParameters,
    payerEncryptionParameters,
  ]);
  // const request1 = await requestNetwork.fromRequestId('011b9244fe6bfade3f5eeddea35ba57a0d20042413040dee2ff9c69307fdaf63fe');
  console.log(
    `The request will be created with ID ${request1.requestId} -------------------------------------------`,
  );
  console.log(`Waiting for confirmation...`);
  await request1.waitForConfirmation();
  console.log(`Creation confirmed!`);

  const disclosedProof = await request1.getSelectDisclosureProof([
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.SALT,
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.CHAINID,
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.FEEADDRESS,
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.FEEAMOUNT,
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.PAYMENTADDRESS,
    RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.REFUNDADDRESS,
    // RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.PAYMENTINFO,
    // RequestNetwork.Types.RequestLogic.PN_ERC20PROXYFEE_INDEX_PARAMS.REFUNDINFO,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.PAYEE,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.PAYER,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.TIMESTAMP,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.NONCE,
    RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.EXPECTEDAMOUNT,
    RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.CURRENCY,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.CONTENTDATA_ROOT,
    // RequestNetwork.Types.RequestLogic.REQUEST_INDEX_PARAMS.PN_ROOT,
  ]);

  console.log('disclosedProof --------------------------');
  // console.log(JSON.stringify(disclosedProof));
  // console.log(disclosedProof.merkleproofs);

  // console.log(disclosedProof.merkleproofs);
  console.log(disclosedProof);

  console.log('--------------------------------------');
  //   console.log(await convertUint8ArrayToHexAsync(disclosedProof.merkleproofs));

  console.log('--------------------------------------');
  console.log('--------------------------------------');

  const valid = await requestNetwork.checkSelectDisclosureProof(disclosedProof);
  console.log(valid);

  console.log();
  console.log(
    `The request will be accepted by the payer -------------------------------------------`,
  );
  await request1.accept(payerIdentity);
  console.log(`Accept confirmed!`);
  /*
  console.log();
  console.log(`The request will be paid by the payer -------------------------------------------`);
  const paymentReq1 = await RequestPaymentProcessor.payErc20FeeProxyRequest(request1.getData(), wallet);
  console.log(`Waiting for confirmation...`);
  await paymentReq1.wait();
  console.log(`Payment confirmed!`);

  console.log();
  console.log('Let\' refresh the request\s data, just in case...');
  console.log(await request1.refresh());
  console.log(`Done!`);

  const reqProofs = request1.getData().proofs;
  console.log();
  console.log("Here the proofs in request's data:");
  console.log(reqProofs);

  const proofs = {
    requestid: request1.requestId,
    requestErc20FeeProxy: reqProofs[0],
    accept: reqProofs[1],
    checkBalanceErc20FeeProxy: await request1.getPaymentProof()
  }

  console.log();
  console.log('######### JSON PROOFS ############');
  console.log(JSON.stringify(proofs))
  

  const proofsJSON = require(`./data/proof.json`);
  // TODO CHECK about currency !
  console.log('## Create')
  console.log('verified:', await requestNetwork.verifyProof('requestErc20FeeProxy', proofs))
  console.log('## Accept')
  console.log('verified:', await requestNetwork.verifyProof('accept', proofs) && proofsJSON.requestErc20FeeProxy.publicSignals[0] == proofsJSON.accept.publicSignals[0])
  console.log('## Payment')
  console.log('Payment address:', '0x'+BigInt(proofsJSON.checkBalanceErc20FeeProxy.publicSignals[3]).toString(16))
  console.log('Payment Reference:', BigInt(proofsJSON.checkBalanceErc20FeeProxy.publicSignals[2]).toString(16).slice(-16))
  console.log('Payment amount declared:', proofsJSON.checkBalanceErc20FeeProxy.publicSignals[1] == "1" ? proofsJSON.checkBalanceErc20FeeProxy.publicSignals[4] : 'unknown')
  console.log('verified:', await requestNetwork.verifyProof('checkBalanceErc20FeeProxy', proofs) 
                                  && proofsJSON.checkBalanceErc20FeeProxy.publicSignals[0] == proofsJSON.accept.publicSignals[0]
                                  && proofsJSON.checkBalanceErc20FeeProxy.publicSignals[1] == "1"
                                  && true // TODO check if amount match the address & reference on the Erc20FeeProxy contract
                                  )
  console.log("/!\\ on chain check required for the payment")
  // TODO
  console.log("## Payee registered")
  console.log("TODO")
  console.log("## Payer registered")
  console.log("TODO")
*/
})();
