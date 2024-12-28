// Import required dependencies
import {
  canonicalize,
  canonicalizeAndGroup,
  createHmac,
  createHmacIdLabelMapFunction,
  selectJsonLd,
  stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives';
import {
  parseBaseProofValue, serializeDisclosureProofValue
} from './proofValue.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

/**
 * Creates a disclosure cryptosuite
 * @param {Object} options Configuration options
 * @param {string} options.proofId Proof identifier
 * @param {Array} options.selectivePointers Array of selective disclosure pointers
 * @returns {Object} The disclosure cryptosuite object
 */
export function createDiscloseCryptosuite({
  proofId, selectivePointers = []
} = {}) {
  const options = {proofId, selectivePointers};
  return {
    name,
    requiredAlgorithm,
    createVerifier: _throwDeriveUsageError,
    createVerifyData: _throwDeriveUsageError,
    createProofValue: _throwDeriveUsageError,
    derive: _derive,
    options
  };
}

/**
 * Creates disclosure data from the provided document and proof
 * @param {Object} options Configuration options
 * @param {Object} options.cryptosuite Cryptosuite instance
 * @param {Object} options.document Document to process
 * @param {Object} options.proof Proof object
 * @param {Function} options.documentLoader Document loader function
 * @returns {Object} The generated disclosure data
 */
async function _createDisclosureData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }
  if(!(cryptosuite.options && typeof cryptosuite.options === 'object')) {
    throw new TypeError(`"cryptosuite.options" must be an object.`);
  }

  const {
    baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
  } = await parseBaseProofValue({proof});

  const {selectivePointers = []} = cryptosuite.options;
  if(!(mandatoryPointers?.length > 0 || selectivePointers?.length > 0)) {
    throw new Error('Nothing selected for disclosure.');
  }

  const hmac = await createHmac({key: hmacKey});
  const labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac});

  const options = {documentLoader};
  const combinedPointers = mandatoryPointers.concat(selectivePointers);
  const {
    groups: {
      mandatory: mandatoryGroup,
      selective: selectiveGroup,
      combined: combinedGroup,
    },
    labelMap
  } = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction,
    groups: {
      mandatory: mandatoryPointers,
      selective: selectivePointers,
      combined: combinedPointers
    },
    options
  });

  let relativeIndex = 0;
  const mandatoryIndexes = [];
  for(const absoluteIndex of combinedGroup.matching.keys()) {
    if(mandatoryGroup.matching.has(absoluteIndex)) {
      mandatoryIndexes.push(relativeIndex);
    }
    relativeIndex++;
  }

  let index = 0;
  const filteredSignatures = signatures.filter(() => {
    while(mandatoryGroup.matching.has(index)) {
      index++;
    }
    return selectiveGroup.matching.has(index++);
  });

  const revealDoc = selectJsonLd({document, pointers: combinedPointers});

  let canonicalIdMap = new Map();
  await canonicalize(
    combinedGroup.deskolemizedNQuads.join(''),
    {...options, inputFormat: 'application/n-quads', canonicalIdMap});
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap);

  const verifierLabelMap = new Map();
  for(const [inputLabel, verifierLabel] of canonicalIdMap) {
    verifierLabelMap.set(verifierLabel, labelMap.get(inputLabel));
  }

  return {
    baseSignature, publicKey, signatures: filteredSignatures,
    labelMap: verifierLabelMap, mandatoryIndexes,
    revealDoc
  };
}

/**
 * Derives a new proof from an existing base proof
 * @param {Object} options Configuration options 
 * @param {Object} options.cryptosuite Cryptosuite instance
 * @param {Object} options.document Source document
 * @param {Object} options.purpose Proof purpose
 * @param {Array} options.proofSet Set of available proofs
 * @param {Function} options.documentLoader Document loader function
 * @param {Object} options.dataIntegrityProof Data integrity proof object
 * @returns {Object} The derived proof document
 */
async function _derive({
  cryptosuite, document, purpose, proofSet,
  documentLoader, dataIntegrityProof
}) {
  const {options: {proofId}} = cryptosuite;
  const baseProof = await _findProof({proofId, proofSet, dataIntegrityProof});

  if(baseProof.proofPurpose !== purpose.term) {
    throw new Error(
      'Base proof purpose does not match purpose for derived proof.');
  }

  const {
    baseSignature, publicKey, signatures, labelMap, mandatoryIndexes, revealDoc
  } = await _createDisclosureData(
    {cryptosuite, document, proof: baseProof, documentLoader});

  const newProof = {...baseProof};
  newProof.proofValue = await serializeDisclosureProofValue(
    {baseSignature, publicKey, signatures, labelMap, mandatoryIndexes});

  delete newProof['@context'];
  revealDoc.proof = newProof;
  return revealDoc;
}

/**
 * Finds a matching proof from the proof set
 * @param {Object} options Configuration options
 * @param {string} options.proofId Optional proof identifier
 * @param {Array} options.proofSet Set of available proofs
 * @param {Object} options.dataIntegrityProof Data integrity proof object
 * @returns {Object} The matched proof
 * @throws {Error} If no matching proof is found or multiple matches exist
 */
async function _findProof({proofId, proofSet, dataIntegrityProof}) {
  let proof;
  if(proofId) {
    proof = proofSet.find(p => p.id === proofId);
  } else {
    for(const p of proofSet) {
      if(await dataIntegrityProof.matchProof({proof: p})) {
        if(proof) {
          throw new Error(
            'Multiple matching proofs; a "proofId" must be specified.');
        }
        proof = p;
      }
    }
  }
  if(!proof) {
    throw new Error(
      'No matching base proof found from which to derive a disclosure proof.');
  }
  return proof;
}

/**
 * Throws error when attempting to use derive functionality incorrectly
 * @throws {Error} Derive usage error
 */
function _throwDeriveUsageError() {
  throw new Error('This cryptosuite must only be used with "derive".');
}
