import * as snarkjs from 'snarkjs';
import { unpackPublicKey, unpackSignature } from '@zk-kit/eddsa-poseidon';
import { bigIntToHexadecimal, hexadecimalToBigInt, hexadecimalToBuffer } from '@zk-kit/utils';
import { poseidon as iden3Poseidon } from '@iden3/js-crypto';

import {
  IdentityTypes,
  ExtensionTypes,
  RequestLogicTypes,
  SignatureProviderTypes,
} from '@requestnetwork/types';

// const PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX = -128;
const PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX = -64;

export {
  generateProof,
  computeRequestIdCircom,
  computeRequestMerkleTrees,
  checkSelectDisclosureProof,
  getSelectDisclosureProof,
};

function poseidon(a: any[]): bigint {
  return iden3Poseidon.hash(a.map(BigInt));
}

function stringToHex(str: string): string {
  let hexStr = '';
  for (let i = 0; i < str.length; i++) {
    hexStr += str.charCodeAt(i).toString(16);
  }
  return hexStr;
}

async function getSelectDisclosureProof(
  requestData: RequestLogicTypes.ICreateParameters | RequestLogicTypes.IRequest,
  indexToDisclose: any[],
): Promise<any> {
  const mks = await computeRequestMerkleTrees(requestData);

  const pnIndexes = indexToDisclose.filter(
    (v) =>
      v >= RequestLogicTypes.PN_ERC20PROXYFEE_INDEX_PARAMS.SALT &&
      v <= RequestLogicTypes.PN_ERC20PROXYFEE_INDEX_PARAMS.REFUNDINFO,
  );
  const reqIndexes = indexToDisclose.filter(
    (v) =>
      v >= RequestLogicTypes.REQUEST_INDEX_PARAMS.PAYEE &&
      v <= RequestLogicTypes.REQUEST_INDEX_PARAMS.CONTENTDATA_ROOT,
  );

  if (pnIndexes.length !== 0) {
    reqIndexes.push(RequestLogicTypes.REQUEST_INDEX_PARAMS.PN_ROOT);
  }

  return [
    mks[0].root,
    mks[0].createMultiProof(reqIndexes),
    mks[1].createMultiProof(pnIndexes.map((v) => v - 10)),
  ];
}

async function checkSelectDisclosureProof(proofs: any): Promise<boolean> {
  // const root = proofs[0].toString('hex');
  const proofReq = proofs[1];
  const proofPN = proofs[2];

  const isValidReq = true; //await validMerkleProof(root, proofReq);

  let isValidPN = false;
  if (proofReq[3] && proofReq[3][7]) {
    const rootPN = proofReq[3][7];

    isValidPN = await validMerkleProof(rootPN, proofPN);
  } else {
    isValidPN = true;
  }

  return isValidPN && isValidReq;
}

async function validMerkleProof(root: bigint, proof: any): Promise<boolean> {
  const l1 = [].concat(proof[0]);
  const l2 = [].concat(proof[1]);
  const l3 = [].concat(proof[2]);
  const leaves = [].concat(proof[3]);

  const l3Computed = await Promise.all(
    l3.map(async (v, i) => v || (leaves[i] ? await poseidon([i, leaves[i], 1]) : null)),
  );

  const l2Computed = await Promise.all(
    l2.map(async (v, i) => {
      if (v) return v;
      const result =
        l3Computed[i * 2] && l3Computed[i * 2 + 1]
          ? await poseidon([l3Computed[i * 2], l3Computed[i * 2 + 1]])
          : null;
      return result;
    }),
  );

  const l1Computed = await Promise.all(
    l1.map(async (v, i) => {
      if (v) return v;
      return l2Computed[i * 2] && l2Computed[i * 2 + 1]
        ? await poseidon([l2Computed[i * 2], l2Computed[i * 2 + 1]])
        : null;
    }),
  );

  const computedRoot = await poseidon([l1Computed[0], l1Computed[1]]);

  return root === computedRoot;
}

class MerlkeTreeRequest {
  root = '';
  l1 = [null, null];
  l2 = [null, null, null, null];
  l3 = [null];
  leaves;
  hash;

  constructor(_leaves: any, _hash: any) {
    if (_leaves.length !== 8) {
      throw 'leaves size wrong';
    }
    this.leaves = _leaves;
    this.hash = _hash;

    this.l3 = this.leaves.map((v: any, i: any) => {
      return this.hash([i, v, 1]);
    });
    this.l2 = this.l2.map((_, i) => this.hash([this.l3[i * 2], this.l3[i * 2 + 1]]));
    this.l1 = this.l1.map((_, i) => this.hash([this.l2[i * 2], this.l2[i * 2 + 1]]));

    this.root = this.hash([this.l1[0], this.l1[1]]);
  }

  createMultiProof(indexToShow: any[] = []) {
    if (indexToShow.length === 0) {
      return [];
    }

    const l1Show = this.l1.map((h, i) =>
      // show the hash only if all the element below are not to show
      indexToShow.every((v) => v < i * 4 || v > i * 4 + 3)
        ? h /* Buffer.from(h!).toString('hex') */
        : null,
    );
    const l2Show = this.l2.map((h, i) =>
      // show the hash only if all the element below are not to show AND the parent is not to show
      !l1Show[Math.floor(i / 2)] && indexToShow.every((v) => v < i * 2 || v > i * 2 + 1)
        ? h /* Buffer.from(h!).toString('hex') */
        : null,
    );
    const l3Show = this.l3.map(
      (h: any, i: any) =>
        // the parents is not to show && the leaf is not to show
        l1Show[Math.floor(i / 4)] || l2Show[Math.floor(i / 2)] || indexToShow.includes(i)
          ? null
          : h /* Buffer.from(h!).toString('hex') */,
    );

    const leavesShow = this.leaves.map((v: any, i: any) => (indexToShow.includes(i) ? v : null));

    return [l1Show, l2Show, l3Show, leavesShow];
  }
}

function computeRequestMerkleTrees(
  requestParameters: RequestLogicTypes.ICreateParameters | RequestLogicTypes.IRequest,
): any[] {
  const pn = requestParameters.extensionsData?.find(
    (e) => e.id === ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT,
  );
  if (!pn) {
    throw Error(
      `Implemented only for ${ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT}`,
    );
  }
  // const contentData = requestParameters.extensionsData?.find(e => e.id === ExtensionTypes.OTHER_ID.CONTENT_DATA);
  // TODO
  const contentDataHash = 0;
  // if(contentData) {
  //     contentDataHash = await poseidon(contentData.)
  // }

  // const salt = '0x4d52102fe8937d3b'; // '0x'+pn.parameters.salt;
  const salt = '0x' + pn.parameters.salt;
  const chainId = 1; // TODO FROM pn.version or currency

  const currencyType = BigInt(stringToHex(requestParameters.currency.type));
  const currencyNetwork = BigInt(stringToHex(requestParameters.currency.network || '  '));
  const currencyHash = poseidon([currencyType, requestParameters.currency.value, currencyNetwork]);
  // {
  //     type: 'ERC20',
  //     value: '0x9FBDa871d559710256a2502A2517b794B482Db40',
  //     network: 'private'
  //   }
  const nonce = requestParameters.nonce || 0;

  const paymentNetworkLeaves = [
    hexadecimalToBigInt(salt),
    chainId,
    hexadecimalToBigInt(pn.parameters.feeAddress),
    hexadecimalToBigInt(pn.parameters.feeAmount),
    hexadecimalToBigInt(pn.parameters.paymentAddress),
    hexadecimalToBigInt(pn.parameters.refundAddress),
    0,
    0,
  ];
  const pnMerkleTree = new MerlkeTreeRequest(paymentNetworkLeaves, poseidon);

  const requestLeaves = [
    hexadecimalToBigInt(requestParameters.payee!.value), // F.toObject(Buffer.from(requestParameters.payee!.value, 'hex')),
    hexadecimalToBigInt(requestParameters.payer!.value), // F.toObject(Buffer.from(requestParameters.payer!.value, 'hex')),
    0, // requestParameters.timestamp,
    nonce,

    requestParameters.expectedAmount,
    currencyHash, // F.toObject(currencyHash),
    contentDataHash,
    pnMerkleTree.root, // F.toObject(pnMerkleTree.root),
  ];

  const reqMerkleTree = new MerlkeTreeRequest(requestLeaves, poseidon);

  return [reqMerkleTree, pnMerkleTree];
}

function computeRequestIdCircom(
  requestParameters: RequestLogicTypes.ICreateParameters | RequestLogicTypes.IRequest,
): RequestLogicTypes.RequestIdCircom {
  const mts: any[] = computeRequestMerkleTrees(requestParameters);
  return mts[0].root;
}

async function generateProof(
  name: string,
  parameters: RequestLogicTypes.ICreateParameters | RequestLogicTypes.IAcceptParameters,
  signatureProvider?: SignatureProviderTypes.ISignatureProvider,
  requestState?: RequestLogicTypes.IRequest | null,
  amountPaid?: RequestLogicTypes.Amount, // TODO surcharge here is bad
): Promise<any> {
  let inputs;

  if (name === 'requestErc20FeeProxy') {
    inputs = await createInputs(
      parameters as RequestLogicTypes.ICreateParameters,
      signatureProvider,
    );
  } else if (name === 'accept') {
    inputs = await acceptInputs(signatureProvider, requestState);
  } else if (name === 'checkBalanceErc20FeeProxy') {
    inputs = await checkBalanceErc20FeeProxyInputs(requestState, amountPaid);
  } else {
    throw Error('Not implemented');
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    // TODO relative path
    `/home/vincent/Documents/request/requestnetwork/packages/request-logic/src/circom/${name}.wasm`,
    `/home/vincent/Documents/request/requestnetwork/packages/request-logic/src/circom/${name}_final.zkey`,
  );

  return { proof, publicSignals };
}

async function createInputs(
  requestParameters: RequestLogicTypes.ICreateParameters,
  signatureProvider?: SignatureProviderTypes.ISignatureProvider,
): Promise<any> {
  if (!signatureProvider) {
    throw Error('must have a signatureProvider');
  }

  const pn = requestParameters.extensionsData?.find(
    (e) => e.id === ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT,
  );
  if (!pn) {
    throw Error(
      `Implemented only for ${ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT}`,
    );
  }
  // const contentData = requestParameters.extensionsData?.find(e => e.id === ExtensionTypes.OTHER_ID.CONTENT_DATA);
  // TODO
  const contentDataHash = 0;
  // if(contentData) {
  //     contentDataHash = await poseidon(contentData.)
  // }

  const salt = '0x' + pn.parameters.salt;
  const chainId = 1; // TODO FROM pn.version or currency

  const currencyType = BigInt(stringToHex(requestParameters.currency.type));
  const currencyNetwork = BigInt(stringToHex(requestParameters.currency.network || '  '));
  const currencyHash = await poseidon([
    currencyType,
    requestParameters.currency.value,
    currencyNetwork,
  ]);

  const nonce = requestParameters.nonce || 0;

  const paymentNetworkLeaves = [
    hexadecimalToBigInt(salt),
    chainId,
    hexadecimalToBigInt(pn.parameters.feeAddress),
    hexadecimalToBigInt(pn.parameters.feeAmount),
    hexadecimalToBigInt(pn.parameters.paymentAddress),
    hexadecimalToBigInt(pn.parameters.refundAddress),
    0,
    0,
  ];

  // const pnMerkleTree = new MerlkeTreeRequest(paymentNetworkLeaves, poseidon);

  const requestLeaves = [
    hexadecimalToBigInt(requestParameters.payer!.value), // F.toObject(Buffer.from(requestParameters.payer!.value, 'hex')),
    0, // requestParameters.timestamp,
    nonce,
    requestParameters.expectedAmount,
    currencyHash, // F.toObject(currencyHash),
    contentDataHash,
    // F.toObject(pnMerkleTree.root),
  ];

  // TODO TODO TODO
  const treeRoot = await computeRequestIdCircom(requestParameters);

  if (
    !requestParameters.payee ||
    requestParameters.payee.type !== IdentityTypes.TYPE.POSEIDON_ADDRESS
  ) {
    throw Error('Payee must be given and POSEIDON itdentity'); // TODO
  }

  const signedData = await signatureProvider.sign(
    '0x' + bigIntToHexadecimal(BigInt(treeRoot)),
    // '0x' + Buffer.from(treeRoot).toString('hex'),
    requestParameters.payee,
    true,
  );

  const pubkeyHex = signedData.signature.value.slice(PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX);
  const packedSignatureHex = signedData.signature.value.slice(
    0,
    PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX,
  );

  const pubBigInt = hexadecimalToBigInt(pubkeyHex);
  const unpackedPub = unpackPublicKey(pubBigInt);

  // console.log('unpackedPub')
  // console.log(unpackedPub)

  // const publicKeyLength = pubkeyHex.length / 2;
  // const Ax = bigIntToHexadecimal(unpackedPub[0]); // Buffer.from(pubkeyHex.slice(0, publicKeyLength), 'hex');
  // const Ay = bigIntToHexadecimal(unpackedPub[1]); // Buffer.from(pubkeyHex.slice(publicKeyLength, publicKeyLength * 2), 'hex');

  console.log('packedSignatureHex');
  console.log(packedSignatureHex);

  // const signatureBuff = eddsa.unpackSignature(Buffer.from(packedSignatureHex, 'hex'));
  // const signatureBuff = unpackSignature(Buffer.from(packedSignatureHex, 'hex'));
  const signatureBuff = unpackSignature(hexadecimalToBuffer(packedSignatureHex));

  console.log('signatureBuff');
  console.log(signatureBuff);

  const inputs = {
    requestInputs: requestLeaves,
    paymentNetworkInputs: paymentNetworkLeaves,
    Ax: unpackedPub[0], // : F.toObject(Ax),
    Ay: unpackedPub[1], //: F.toObject(Ay),
    R8x: signatureBuff.R8[0], //: F.toObject(signatureBuff.R8[0]),
    R8y: signatureBuff.R8[1], //F.toObject(signatureBuff.R8[1]),
    S: signatureBuff.S,
  };
  console.log(inputs);
  return inputs;
}

async function acceptInputs(
  signatureProvider?: SignatureProviderTypes.ISignatureProvider,
  requestState?: RequestLogicTypes.IRequest | null,
): Promise<any> {
  if (!signatureProvider) {
    throw Error('must have a signatureProvider');
  }
  if (!requestState) {
    throw Error('request must have a state');
  }

  if (!requestState.payee || requestState.payee.type !== IdentityTypes.TYPE.POSEIDON_ADDRESS) {
    throw Error('Payee must be given and POSEIDON itdentity'); // TODO
  }
  if (!requestState.payer || requestState.payer.type !== IdentityTypes.TYPE.POSEIDON_ADDRESS) {
    throw Error('Payer must be given and POSEIDON itdentity'); // TODO
  }

  const pn = requestState.extensionsData?.find(
    (e) => e.id === ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT,
  );
  if (!pn) {
    throw Error(
      `Implemented only for ${ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT}`,
    );
  }
  // const contentData = requestState.extensionsData?.find(e => e.id === ExtensionTypes.OTHER_ID.CONTENT_DATA);
  // TODO
  const contentDataHash = 0;
  // if(contentData) {
  //     contentDataHash = await poseidon(contentData.)
  // }

  // const salt = '0x4d52102fe8937d3b'; // '0x'+pn.parameters.salt;
  const salt = '0x' + pn.parameters.salt;
  const chainId = 1; // TODO FROM pn.version or currency

  const currencyType = BigInt(stringToHex(requestState.currency.type));
  const currencyNetwork = BigInt(stringToHex(requestState.currency.network || '  '));
  const currencyHash = await poseidon([currencyType, requestState.currency.value, currencyNetwork]);

  const nonce = requestState.nonce || 0;

  const paymentNetworkLeaves = [
    hexadecimalToBigInt(salt),
    chainId,
    hexadecimalToBigInt(pn.parameters.feeAddress),
    hexadecimalToBigInt(pn.parameters.feeAmount),
    hexadecimalToBigInt(pn.parameters.paymentAddress),
    hexadecimalToBigInt(pn.parameters.refundAddress),
    0,
    0,
  ];
  const pnMerkleTree = new MerlkeTreeRequest(paymentNetworkLeaves, poseidon);

  const requestLeaves = [
    hexadecimalToBigInt(requestState.payee!.value), // F.toObject(Buffer.from(requestState.payee!.value, 'hex')),
    hexadecimalToBigInt(requestState.payer!.value), // F.toObject(Buffer.from(requestState.payer!.value, 'hex')),
    requestState.timestamp,
    nonce,
    requestState.expectedAmount,
    currencyHash, // F.toObject(currencyHash),
    contentDataHash,
    pnMerkleTree.root, // F.toObject(pnMerkleTree.root),
  ];
  const reqMerkleTree = new MerlkeTreeRequest(requestLeaves, poseidon);

  const treeRoot = reqMerkleTree.root;
  const h0 = reqMerkleTree.l3[0];
  const hB = reqMerkleTree.l2[1];
  const hCD = reqMerkleTree.l1[1];
  // const h0 = leavesRequest[0];
  // const hB = level2Request[1];
  // const hCD = level1Request[1];

  //       root
  //    AB      CD
  //  A   B   C   D
  // 0 1 2 3 4 5 6 7

  const signedData = await signatureProvider.sign(
    '0x' + bigIntToHexadecimal(BigInt(treeRoot)),
    // '0x' + Buffer.from(treeRoot).toString('hex'),
    requestState.payer,
    true,
  );

  const pubkeyHex = signedData.signature.value.slice(PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX);
  const packedSignatureHex = signedData.signature.value.slice(
    0,
    PUBKEY_POSITION_FROM_END_IN_EDDSA_HEX,
  );

  const pubBigInt = hexadecimalToBigInt(pubkeyHex);
  const unpackedPub = unpackPublicKey(pubBigInt);

  // const signatureBuff = eddsa.unpackSignature(Buffer.from(packedSignatureHex, 'hex'));
  const signatureBuff = unpackSignature(Buffer.from(packedSignatureHex, 'hex'));

  const inputs = {
    h0, //: F.toObject(h0),
    hB, //: F.toObject(hB),
    hCD, //: F.toObject(hCD),

    Ax: unpackedPub[0], //: F.toObject(Ax),
    Ay: unpackedPub[1], //: F.toObject(Ay),
    R8x: signatureBuff.R8[0], //F.toObject(signatureBuff.R8[0]),
    R8y: signatureBuff.R8[1], // F.toObject(signatureBuff.R8[1]),
    S: signatureBuff.S,
  };

  return inputs;
}

async function checkBalanceErc20FeeProxyInputs(
  requestState?: RequestLogicTypes.IRequest | null,
  amountPaid?: RequestLogicTypes.Amount, // TODO Balance (take in account refunds)
): Promise<any> {
  if (!requestState) {
    throw Error('request must have a state');
  }
  if (!amountPaid) {
    throw Error('amountPaid must be given');
  }

  if (!requestState.payee || requestState.payee.type !== IdentityTypes.TYPE.POSEIDON_ADDRESS) {
    throw Error('Payee must be given and POSEIDON itdentity'); // TODO
  }
  if (!requestState.payer || requestState.payer.type !== IdentityTypes.TYPE.POSEIDON_ADDRESS) {
    throw Error('Payer must be given and POSEIDON itdentity'); // TODO
  }

  const pn = requestState.extensionsData?.find(
    (e) => e.id === ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT,
  );
  if (!pn) {
    throw Error(
      `Implemented only for ${ExtensionTypes.PAYMENT_NETWORK_ID.ERC20_FEE_PROXY_CONTRACT}`,
    );
  }
  // const contentData = requestState.extensionsData?.find(e => e.id === ExtensionTypes.OTHER_ID.CONTENT_DATA);
  // TODO
  const contentDataHash = 0;
  // if(contentData) {
  //     contentDataHash = await poseidon(contentData.)
  // }

  // const salt = '0x4d52102fe8937d3b'; // '0x'+pn.parameters.salt;
  const salt = '0x' + pn.parameters.salt;
  const chainId = 1; // TODO FROM pn.version or currency

  const currencyType = BigInt(stringToHex(requestState.currency.type));
  const currencyNetwork = BigInt(stringToHex(requestState.currency.network || '  '));
  const currencyHash = await poseidon([currencyType, requestState.currency.value, currencyNetwork]);

  const nonce = requestState.nonce || 0;

  const paymentNetworkLeaves = [
    hexadecimalToBigInt(salt),
    chainId,
    hexadecimalToBigInt(pn.parameters.feeAddress),
    hexadecimalToBigInt(pn.parameters.feeAmount),
    hexadecimalToBigInt(pn.parameters.paymentAddress),
    hexadecimalToBigInt(pn.parameters.refundAddress),
    0,
    0,
  ];
  // const pnMerkleTree = new MerlkeTreeRequest(paymentNetworkLeaves, poseidon);

  const requestLeaves = [
    hexadecimalToBigInt(requestState.payee!.value), // F.toObject(Buffer.from(requestState.payee!.value, 'hex')),
    hexadecimalToBigInt(requestState.payer!.value), // F.toObject(Buffer.from(requestState.payer!.value, 'hex')),
    requestState.timestamp,
    nonce,
    requestState.expectedAmount,
    currencyHash, // F.toObject(currencyHash),
    contentDataHash,
    // F.toObject(pnMerkleTree.root)
  ];

  const inputs = {
    requestInputs: requestLeaves,
    paymentNetworkInputs: paymentNetworkLeaves,
    amountPaid,
  };

  return inputs;
}
