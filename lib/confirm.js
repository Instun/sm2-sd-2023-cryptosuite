// Import required dependencies
import {
  createHmac,
  createHmacIdLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  labelReplacementCanonicalizeJsonLd,
  selectJsonLd
} from '@digitalbazaar/di-sd-primitives';
import { createVerifier } from './verify.js';
import { name } from './name.js';
import { parseBaseProofValue } from './proofValue.js';
import { requiredAlgorithm } from './requiredAlgorithm.js';

/**
 * Creates a confirmation cryptosuite
 * @returns {Object} The confirmation cryptosuite object
 */
export function createConfirmCryptosuite() {
  return {
    name,
    requiredAlgorithm,
    createVerifier,
    createVerifyData: _createVerifyData
  };
}

/**
 * Creates verification data for confirmation
 * @param {Object} options Configuration options
 * @param {Object} options.cryptosuite Cryptosuite instance
 * @param {Object} options.document Document to verify
 * @param {Object} options.proof Proof object
 * @param {Function} options.documentLoader Document loader function
 * @returns {Object} The verification data
 */
async function _createVerifyData({
  cryptosuite, document, proof, documentLoader
}) {
  if (cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }

  const options = { documentLoader };
  const proofHashPromise = hashCanonizedProof({ document, proof, options })
    .catch(e => e);

  const {
    baseSignature, hmacKey, publicKey, signatures, mandatoryPointers,
  } = await parseBaseProofValue({ proof });

  const hmac = await createHmac({ key: hmacKey });
  const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac });
  const nquads = await labelReplacementCanonicalizeJsonLd({
    document,
    labelMapFactoryFunction,
    options
  });

  let mandatory;
  if (mandatoryPointers.length === 0) {
    mandatory = [];
  } else {
    const filteredDocument = await selectJsonLd({
      document,
      pointers: mandatoryPointers
    });
    mandatory = await labelReplacementCanonicalizeJsonLd({
      document: filteredDocument,
      labelMapFactoryFunction,
      options
    });
  }

  const nonMandatory = nquads.filter(nquad => !mandatory.includes(nquad));

  const { mandatoryHash } = await hashMandatory({ mandatory });

  const proofHash = await proofHashPromise;
  if (proofHash instanceof Error) {
    throw proofHash;
  }
  return {
    baseSignature, proofHash, publicKey, signatures, nonMandatory,
    mandatoryHash
  };
}
