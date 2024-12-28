// Import required dependencies
import * as base58 from 'base58-universal';
import { SM2Multikey } from '@instun/sm2-multikey';
import {
  createLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  labelReplacementCanonicalizeJsonLd,
  stringToUtf8Bytes
} from '@digitalbazaar/di-sd-primitives';
import {
  parseDisclosureProofValue,
  serializeBaseVerifyData
} from './proofValue.js';
import {requiredAlgorithm as _requiredAlgorithm} from './requiredAlgorithm.js';
import {name} from './name.js';

/**
 * Creates a verification cryptosuite
 * @param {Object} options Configuration options
 * @param {string} options.requiredAlgorithm Required algorithm, defaults to SM2
 * @returns {Object} The verification cryptosuite object
 */
export function createVerifyCryptosuite({
  requiredAlgorithm = _requiredAlgorithm
} = {}) {
  return {
    name,
    requiredAlgorithm,
    createVerifier,
    createVerifyData: _createVerifyData
  };
}

/**
 * Creates a verifier instance
 * @param {Object} options Configuration options 
 * @param {Object} options.verificationMethod Verification method
 * @returns {Object} The verifier object containing algorithm, id and verify method
 */
export async function createVerifier({verificationMethod}) {
  const key = await SM2Multikey.from(verificationMethod);
  const verifier = key.verifier();
  return {
    algorithm: verifier.algorithm,
    id: verifier.id,
    async verify({data}) {
      return _multiverify({verifier, data});
    }
  };
}

/**
 * Creates verification data
 * @param {Object} options Configuration options
 * @param {Object} options.cryptosuite The cryptosuite
 * @param {Object} options.document The document to verify
 * @param {Object} options.proof The proof object
 * @param {Function} options.documentLoader Document loader function
 * @returns {Object} The verification data object
 */
async function _createVerifyData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }

  const options = {documentLoader};
  const proofHashPromise = hashCanonizedProof({document, proof, options})
    .catch(e => e);

  const {
    baseSignature, publicKey, signatures, labelMap, mandatoryIndexes
  } = await parseDisclosureProofValue({proof});

  const labelMapFactoryFunction = await createLabelMapFunction({labelMap});
  const nquads = await labelReplacementCanonicalizeJsonLd(
    {document, labelMapFactoryFunction, options});

  const mandatory = [];
  const nonMandatory = [];
  for(const [index, nq] of nquads.entries()) {
    if(mandatoryIndexes.includes(index)) {
      mandatory.push(nq);
    } else {
      nonMandatory.push(nq);
    }
  }

  const {mandatoryHash} = await hashMandatory({mandatory});

  const proofHash = await proofHashPromise;
  if(proofHash instanceof Error) {
    throw proofHash;
  }
  return {
    baseSignature, proofHash, publicKey, signatures, nonMandatory,
    mandatoryHash
  };
}

/**
 * Performs multiple verifications
 * @param {Object} options Configuration options
 * @param {Object} options.verifier The verifier instance
 * @param {Object} options.data The data to verify
 * @returns {boolean} The verification result
 */
async function _multiverify({verifier, data} = {}) {
  const {
    baseSignature, proofHash, publicKey, signatures,
    nonMandatory, mandatoryHash
  } = data;

  const publicKeyMultibase = 'z' + base58.encode(publicKey);
  const localKeyPair = await SM2Multikey.from({publicKeyMultibase});

  if(signatures.length !== nonMandatory.length) {
    throw new Error(
      `Signature count (${signatures.length}) does not match ` +
      `non-mandatory message count (${nonMandatory.length}).`);
  }
  const {verify} = localKeyPair.verifier();
  const results = await Promise.all(signatures.map(
    (signature, index) => verify({
      data: stringToUtf8Bytes(nonMandatory[index]),
      signature
    })));
  if(results.some(r => !r)) {
    return false;
  }

  const toVerify = await serializeBaseVerifyData(
    {proofHash, publicKey, mandatoryHash});
  return verifier.verify({data: toVerify, signature: baseSignature});
}
