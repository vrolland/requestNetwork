import {
  derivePublicKey,
  packPublicKey,
  unpackPublicKey,
  packSignature,
  unpackSignature,
  signMessage,
  verifySignature,
} from '@zk-kit/eddsa-poseidon';

import { bigIntToHexadecimal, hexadecimalToBigInt, hexadecimalToBuffer } from '@zk-kit/utils';

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
  // const poseidon = await circomlibjs.buildPoseidon();
  // const hashBuff = await poseidon(Buffer.from(data));
  // return Buffer.from(hashBuff).toString('hex');
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
  // const eddsa = await circomlibjs.buildEddsa();
  // const publicKey = eddsa.prv2pub(Buffer.from(privateKey, "hex"));
  // const publicKeyHex = Buffer.from([...publicKey[0], ...publicKey[1]]).toString('hex');
  // return publicKeyHex;

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
  // const poseidon = await circomlibjs.buildPoseidon();

  // const publicKeyLength = publicKey.length / 2;
  // const Ax = Buffer.from(publicKey.slice(0,publicKeyLength), 'hex');
  // const Ay = Buffer.from(publicKey.slice(publicKeyLength,publicKeyLength*2), 'hex');

  // const address = await poseidon([Ax, Ay]);
  // return Buffer.from(address).toString('hex');

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
  // const eddsa = await circomlibjs.buildEddsa();
  // const payeePrivBuff = Buffer.from(privateKey, "hex");
  // const dataBuff = Buffer.from(data.slice(2), "hex");

  // const signature = await eddsa.signPoseidon(payeePrivBuff, dataBuff);

  // return Buffer.from(eddsa.packSignature(signature)).toString('hex');
  const dataBuff = hexadecimalToBigInt(data);
  const privateKeyBuff = Buffer.from(privateKey, 'hex');

  const signature = signMessage(privateKeyBuff, dataBuff);
  return packSignature(signature).toString('hex');
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
  // const eddsa = await circomlibjs.buildEddsa();
  // const unpackedSignatureBuff = eddsa.unpackSignature(Buffer.from(signature, 'hex'));

  // const publicKeyLength = publicKey.length / 2;
  // const Ax = Buffer.from(publicKey.slice(0,publicKeyLength), 'hex');
  // const Ay = Buffer.from(publicKey.slice(publicKeyLength,publicKeyLength*2), 'hex');

  // const dataBuff = Buffer.from(data.slice(2), "hex");

  // return await eddsa.verifyPoseidon(dataBuff, unpackedSignatureBuff, [Ax, Ay])

  const pubBigInt = hexadecimalToBigInt(publicKey);
  const unpackedPub = unpackPublicKey(pubBigInt);

  const dataBuff = hexadecimalToBigInt(data);
  const unpackedSignature = unpackSignature(hexadecimalToBuffer(signature));

  return verifySignature(dataBuff, unpackedSignature, unpackedPub);
}

/*
  async function merkleTree8root(array: unknown[]): Promise<string> {
    if(array.length > 8) {
      throw "This merkle tree can host only 8 values";
    }
    while (array.length<8) array.push(0);
    
    const poseidon = await circomlibjs.buildPoseidon();
    const F = poseidon.F;

    const leaves = await Promise.all(array.map(async (v,i) => poseidon([i, v, 1])));
    const level2 = await Promise.all([
        poseidon(leaves.slice(0,2)),
        poseidon(leaves.slice(2,4)),
        poseidon(leaves.slice(4,6)),
        poseidon(leaves.slice(6,8)),
    ]);
    const level1 = await Promise.all([
        poseidon(level2.slice(0,2)),
        poseidon(level2.slice(2,4)),
    ]);
    const root = await poseidon(level1);

    return F.toObject(root);
  }
*/
