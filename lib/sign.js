// Import required dependencies
import * as base58 from 'base58-universal';
import { SM2Multikey } from '@instun/sm2-multikey';
import {
  canonicalizeAndGroup,
  createHmac,
  createHmacIdLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  stringToUtf8Bytes
} from '@digitalbazaar/di-sd-primitives';
import {
  serializeBaseProofValue,
  serializeBaseVerifyData
} from './proofValue.js';
import {requiredAlgorithm as _requiredAlgorithm} from './requiredAlgorithm.js';
import {name} from './name.js';

/**
 * Creates a signing cryptosuite
 * @param {Object} options Configuration options
 * @param {Array} options.mandatoryPointers Array of mandatory pointer strings
 * @param {string} options.requiredAlgorithm Required algorithm, defaults to SM2
 * @returns {Object} The signing cryptosuite object
 */
export function createSignCryptosuite({
  mandatoryPointers = [], requiredAlgorithm = _requiredAlgorithm
} = {}) {
  const options = {mandatoryPointers};
  return {
    name,
    requiredAlgorithm,
    createVerifier: _throwSignUsageError,
    createVerifyData: _createSignData,
    createProofValue: _createBaseProofValue,
    options
  };
}

/**
 * Creates a base proof value
 * @param {Object} options Configuration options
 * @param {Object} options.verifyData Verification data
 * @param {Object} options.dataIntegrityProof Data integrity proof
 * @returns {string} The base proof value
 */
async function _createBaseProofValue({verifyData, dataIntegrityProof}) {
  const {signer} = dataIntegrityProof;
  const {
    proofHash, mandatoryPointers, mandatoryHash, nonMandatory, hmacKey
  } = verifyData;

  const localKeyPair = await SM2Multikey.generate();
  const {sign} = localKeyPair.signer();
  const signatures = await Promise.all(nonMandatory.map(
    nq => sign({data: stringToUtf8Bytes(nq)})));

  const publicKey = base58.decode(localKeyPair.publicKeyMultibase.slice(1));
  const toSign = await serializeBaseVerifyData(
    {proofHash, publicKey, mandatoryHash});

  const baseSignature = await signer.sign({data: toSign});

  const proofValue = serializeBaseProofValue({
    baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
  });
  return proofValue;
}

/**
 * Creates signing data
 * @param {Object} options Configuration options
 * @param {Object} options.cryptosuite Cryptosuite instance
 * @param {Object} options.document Document to sign
 * @param {Object} options.proof Proof object
 * @param {Function} options.documentLoader Document loader function
 * @returns {Object} The signing data object
 */
async function _createSignData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }
  if(!(cryptosuite.options && typeof cryptosuite.options === 'object')) {
    throw new TypeError(`"cryptosuite.options" must be an object.`);
  }
  const {mandatoryPointers = []} = cryptosuite.options;
  if(!Array.isArray(mandatoryPointers)) {
    throw new TypeError(
      `"cryptosuite.options.mandatoryPointers" must be an array.`);
  }

  const options = {documentLoader};
  const proofHashPromise = hashCanonizedProof({document, proof, options})
    .catch(e => e);

  const hmac = await createHmac({key: null});
  const labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac});

  const {
    groups: {mandatory: mandatoryGroup}
  } = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction,
    groups: {mandatory: mandatoryPointers},
    options
  });
  const mandatory = [...mandatoryGroup.matching.values()];
  const nonMandatory = [...mandatoryGroup.nonMatching.values()];

  const {mandatoryHash} = await hashMandatory({mandatory});

  const hmacKey = await hmac.export();

  const proofHash = await proofHashPromise;
  if(proofHash instanceof Error) {
    throw proofHash;
  }
  return {proofHash, mandatoryPointers, mandatoryHash, nonMandatory, hmacKey};
}

/**
 * Throws error when attempting to use sign functionality incorrectly
 * @throws {Error} Sign usage error
 */
function _throwSignUsageError() {
  throw new Error('This cryptosuite must only be used with "sign".');
}
