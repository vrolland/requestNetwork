import {
  derivePublicKey,
  packPublicKey,
  unpackPublicKey,
  packSignature,
  unpackSignature,
  signMessage,
  verifySignature,
} from '@zk-kit/eddsa-poseidon';

import {
  bigIntToHexadecimal,
  bufferToHexadecimal,
  hexadecimalToBigInt,
  hexadecimalToBuffer,
} from '@zk-kit/utils';

import { poseidon } from '@iden3/js-crypto';

/**
 * Function to manage Elliptic-curve cryptography
 */
export {
  getAddressFromPrivateKey,
  getAddressFromPublicKey,
  getPublicKeyFromPrivateKey,
  //   edRecover,
  edSign,
  edVerify,
  //   merkleTree8root,
  poseidonHash,
};

/**
 * Function to derive the address from an EC private key
 *
 * @param privateKey the private key to derive
 *
 * @returns the address
 */
function getAddressFromPrivateKey(privateKey: string): string {
  const publicKey = derivePublicKey(Buffer.from(privateKey, 'hex'));
  const address = poseidon.hash(publicKey);

  return bigIntToHexadecimal(address);
}

/**
 * Hashes with the poseidon algorithm
 *
 * @param data The string to hash
 * @returns The hashed data multi-formatted
 */
function poseidonHash(data: string): string {
  const hashBigInt = poseidon.hash([hexadecimalToBigInt(data)]);
  return bigIntToHexadecimal(hashBigInt);
}

/**
 * Function to derive the address from an EC public key
 *
 * @param publicKey the public key to derive
 *
 * @returns the address
 */
function getPublicKeyFromPrivateKey(privateKey: string): string {
  const publicKey = derivePublicKey(Buffer.from(privateKey, 'hex'));
  const pubPacked = packPublicKey(publicKey);
  return bigIntToHexadecimal(pubPacked);
}

/**
 * Function to derive the address from an EC public key
 *
 * @param publicKey the public key to derive
 *
 * @returns the address
 */
function getAddressFromPublicKey(publicKey: string): string {
  const pubBigInt = hexadecimalToBigInt(publicKey);
  const unpackedPub = unpackPublicKey(pubBigInt);
  const address = poseidon.hash(unpackedPub);

  return bigIntToHexadecimal(address);
}

/**
 * Function edSigndata with EDDSA
 *
 * @param data the data to sign
 *
 * @returns the signature
 */
function edSign(privateKey: string, data: string): string {
  const dataBuff = hexadecimalToBigInt(data);
  const privateKeyBuff = Buffer.from(privateKey, 'hex');

  const signature = signMessage(privateKeyBuff, dataBuff);
  const packedSignature = packSignature(signature);

  return bufferToHexadecimal(packedSignature);
}

/**
 * Function to recover address from a signature
 *
 * @param signature the signature
 * @param data the data signed
 *
 * @returns the address
 */
// function edRecover(_signature: string, _data: string): string {
//     throw new Error('NOT IMPLEMENTED'); // TODO even possible?
// }

/**
 * Function ecSigndata with EDDSA
 *
 * @param data the data to sign
 *
 * @returns the signature
 */
function edVerify(signature: string, data: string, publicKey: string): boolean {
  const pubBigInt = hexadecimalToBigInt(publicKey);
  const unpackedPub = unpackPublicKey(pubBigInt);

  const dataBuff = hexadecimalToBigInt(data);
  const unpackedSignature = unpackSignature(hexadecimalToBuffer(signature));

  return verifySignature(dataBuff, unpackedSignature, unpackedPub);
}
