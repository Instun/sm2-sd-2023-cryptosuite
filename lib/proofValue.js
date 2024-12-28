import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';

// Define CBOR prefix constants
const CBOR_PREFIX_BASE = new Uint8Array([0xd9, 0x5d, 0x00]);
const CBOR_PREFIX_DERIVED = new Uint8Array([0xd9, 0x5d, 0x01]);

const TAGS = [];
TAGS[64] = _decodeUint8Array;

/**
 * Parses the base proof value
 * @param {Object} options Configuration options
 * @param {Object} options.proof Proof object
 * @returns {Object} Parsed proof parameters
 */
export function parseBaseProofValue({proof} = {}) {
  try {
    const proofValue = base64url.decode(proof.proofValue.slice(1));
    if(!_isBaseProofValue(proof)) {
      throw new TypeError('"proof.proofValue" must be a base proof.');
    }

    const payload = proofValue.subarray(CBOR_PREFIX_BASE.length);
    const [
      baseSignature,
      publicKey,
      hmacKey,
      signatures,
      mandatoryPointers
    ] = cborg.decode(payload, {useMaps: true, tags: TAGS});

    const params = {
      baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
    };
    _validateBaseProofParams(params);
    return params;
  } catch(e) {
    const err = new TypeError(
      'The proof does not include a valid "proofValue" property.');
    err.cause = e;
    throw err;
  }
}

/**
 * Parses the disclosure proof value
 * @param {Object} options Configuration options
 * @param {Object} options.proof Proof object
 * @returns {Object} Parsed proof parameters
 */
export function parseDisclosureProofValue({proof} = {}) {
  try {
    const proofValue = base64url.decode(proof.proofValue.slice(1));
    if(!_isDerivedProofValue(proof)) {
      throw new TypeError('"proof.proofValue" must be a derived proof.');
    }

    const payload = proofValue.subarray(CBOR_PREFIX_DERIVED.length);
    const [
      baseSignature,
      publicKey,
      signatures,
      compressedLabelMap,
      mandatoryIndexes
    ] = cborg.decode(payload, {useMaps: true, tags: TAGS});

    const labelMap = _decompressLabelMap(compressedLabelMap);
    const params = {
      baseSignature, publicKey, signatures, labelMap, mandatoryIndexes
    };
    _validateDerivedProofParams(params);
    return params;
  } catch(e) {
    const err = new TypeError(
      'The proof does not include a valid "proofValue" property.');
    err.cause = e;
    throw err;
  }
}

/**
 * Serializes the base proof value
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.baseSignature Base signature
 * @param {Uint8Array} options.publicKey Public key
 * @param {Uint8Array} options.hmacKey HMAC key
 * @param {Array<Uint8Array>} options.signatures Array of signatures
 * @param {Array<string>} options.mandatoryPointers Array of mandatory pointers
 * @returns {string} Serialized proof value
 */
export function serializeBaseProofValue({
  baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
} = {}) {
  _validateBaseProofParams({
    baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
  });

  const payload = [
    baseSignature,
    publicKey,
    hmacKey,
    signatures,
    mandatoryPointers
  ];
  const cbor = _concatBuffers([
    CBOR_PREFIX_BASE, cborg.encode(payload, {useMaps: true})
  ]);
  return `u${base64url.encode(cbor)}`;
}

/**
 * Serializes the base verify data
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.proofHash Proof hash
 * @param {Uint8Array} options.publicKey Public key
 * @param {Uint8Array} options.mandatoryHash Mandatory hash
 * @returns {Uint8Array} Serialized verify data
 */
export function serializeBaseVerifyData({
  proofHash, publicKey, mandatoryHash
} = {}) {
  _validateBaseVerifyDataParams({proofHash, publicKey, mandatoryHash});

  const verifyData = _concatBuffers([proofHash, publicKey, mandatoryHash]);
  return verifyData;
}

/**
 * Serializes the disclosure proof value
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.baseSignature Base signature
 * @param {Uint8Array} options.publicKey Public key
 * @param {Array<Uint8Array>} options.signatures Array of signatures
 * @param {Map<string, string>} options.labelMap Label map
 * @param {Array<number>} options.mandatoryIndexes Array of mandatory indexes
 * @returns {string} Serialized disclosure proof value
 */
export function serializeDisclosureProofValue({
  baseSignature, publicKey, signatures, labelMap, mandatoryIndexes
} = {}) {
  _validateDerivedProofParams({
    baseSignature, publicKey, signatures, labelMap, mandatoryIndexes
  });

  const payload = [
    baseSignature,
    publicKey,
    signatures,
    _compressLabelMap(labelMap),
    mandatoryIndexes
  ];
  const cbor = _concatBuffers([
    CBOR_PREFIX_DERIVED, cborg.encode(payload, {useMaps: true})
  ]);
  return `u${base64url.encode(cbor)}`;
}

/**
 * Asserts that the proof value is valid
 * @param {Object} proof The proof object to validate
 * @throws {TypeError} If proof value is invalid
 */
function _assertProofValue(proof) {
  if(typeof proof?.proofValue !== 'string') {
    throw new TypeError(
      'The proof does not include a valid "proofValue" property; ' +
      '"proofValue" must be a string.');
  }
  if(proof.proofValue[0] !== 'u') {
    throw new TypeError(
      'The proof does not include a valid "proofValue" property; ' +
      'only base64url multibase encoding is supported.');
  }
}

/**
 * Compresses a label map by converting keys and values
 * @param {Map} labelMap The label map to compress
 * @returns {Map} The compressed label map
 */
function _compressLabelMap(labelMap) {
  const map = new Map();
  for(const [k, v] of labelMap.entries()) {
    map.set(parseInt(k.slice(4), 10), base64url.decode(v.slice(1)));
  }
  return map;
}

/**
 * Concatenates multiple buffers into a single Uint8Array 
 * @param {Array<Uint8Array>} buffers Array of buffers to concatenate
 * @returns {Uint8Array} The concatenated buffer
 */
function _concatBuffers(buffers) {
  const bytes = new Uint8Array(buffers.reduce((acc, b) => acc + b.length, 0));
  let offset = 0;
  for(const b of buffers) {
    bytes.set(b, offset);
    offset += b.length;
  }
  return bytes;
}

/**
 * Decompresses a label map by converting keys and values back
 * @param {Map} compressedLabelMap The compressed label map
 * @returns {Map} The decompressed label map
 */
function _decompressLabelMap(compressedLabelMap) {
  const map = new Map();
  for(const [k, v] of compressedLabelMap.entries()) {
    map.set(`c14n${k}`, `u${base64url.encode(v)}`);
  }
  return map;
}

/**
 * Checks if a proof value is a base proof
 * @param {Object} proof The proof to check
 * @returns {boolean} True if proof is a base proof
 */
function _isBaseProofValue(proof) {
  _assertProofValue(proof);
  const proofValue = base64url.decode(proof.proofValue.slice(1));
  return _startsWithBytes(proofValue, CBOR_PREFIX_BASE);
}

/**
 * Checks if a proof value is a derived proof
 * @param {Object} proof The proof to check
 * @returns {boolean} True if proof is a derived proof
 */
function _isDerivedProofValue(proof) {
  _assertProofValue(proof);
  const proofValue = base64url.decode(proof.proofValue.slice(1));
  return _startsWithBytes(proofValue, CBOR_PREFIX_DERIVED);
}

/**
 * Checks if a buffer starts with specific bytes
 * @param {Uint8Array} buffer The buffer to check
 * @param {Uint8Array} prefix The prefix bytes to match
 * @returns {boolean} True if buffer starts with prefix
 */
function _startsWithBytes(buffer, prefix) {
  for(let i = 0; i < prefix.length; ++i) {
    if(buffer[i] !== prefix[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Validates the base proof parameters
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.baseSignature Base signature
 * @param {Uint8Array} options.publicKey Public key
 * @param {Uint8Array} options.hmacKey HMAC key
 * @param {Array<Uint8Array>} options.signatures Array of signatures
 * @param {Array<string>} options.mandatoryPointers Array of mandatory pointers
 */
function _validateBaseProofParams({
  baseSignature, publicKey, hmacKey, signatures, mandatoryPointers
}) {
  if(!(baseSignature instanceof Uint8Array && baseSignature.length === 64)) {
    throw new TypeError('"baseSignature" must be a Uint8Array of length 64.');
  }
  if(!(publicKey instanceof Uint8Array &&
    publicKey.length === 35)) {
    throw new TypeError('"publicKey" must be a Uint8Array of length 35.');
  }
  if(!(hmacKey instanceof Uint8Array && hmacKey.length === 32)) {
    throw new TypeError('"hmacKey" must be a Uint8Array of length 32.');
  }
  if(!(Array.isArray(signatures) &&
    signatures.every(s => s instanceof Uint8Array && s.length === 64))) {
    throw new TypeError(
      '"signatures" must be an array of Uint8Arrays, each of length 64.');
  }
  if(!(Array.isArray(mandatoryPointers) &&
    mandatoryPointers.every(p => typeof p === 'string'))) {
    throw new TypeError('"mandatoryPointers" must be an array of strings.');
  }
}

/**
 * Validates the base verify data parameters
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.proofHash Proof hash
 * @param {Uint8Array} options.publicKey Public key
 * @param {Uint8Array} options.mandatoryHash Mandatory hash
 */
function _validateBaseVerifyDataParams({
  proofHash, publicKey, mandatoryHash
}) {
  if(!(proofHash instanceof Uint8Array && proofHash.length === 32)) {
    throw new TypeError('"proofHash" must be a Uint8Array of length 32.');
  }
  if(!(publicKey instanceof Uint8Array &&
    publicKey.length === 35)) {
    throw new TypeError('"publicKey" must be a Uint8Array of length 35.');
  }
  if(!(mandatoryHash instanceof Uint8Array && mandatoryHash.length === 32)) {
    throw new TypeError('"mandatoryHash" must be a Uint8Array of length 32.');
  }
}

/**
 * Validates the derived proof parameters
 * @param {Object} options Configuration options
 * @param {Uint8Array} options.baseSignature Base signature
 * @param {Uint8Array} options.publicKey Public key
 * @param {Array<Uint8Array>} options.signatures Array of signatures
 * @param {Map<string, string>} options.labelMap Label map
 * @param {Array<number>} options.mandatoryIndexes Array of mandatory indexes
 */
function _validateDerivedProofParams({
  baseSignature, publicKey, signatures, labelMap, mandatoryIndexes
}) {
  if(!(baseSignature instanceof Uint8Array && baseSignature.length === 64)) {
    throw new TypeError('"baseSignature" must be a Uint8Array of length 64.');
  }
  if(!(publicKey instanceof Uint8Array &&
    publicKey.length === 35)) {
    throw new TypeError('"publicKey" must be a Uint8Array of length 35.');
  }
  if(!(Array.isArray(signatures) &&
    signatures.every(s => s instanceof Uint8Array))) {
    throw new TypeError('"signatures" must be an array of Uint8Arrays.');
  }
  if(!(labelMap instanceof Map &&
    [...labelMap.entries()].every(
      ([k, v]) => typeof k === 'string' && typeof v === 'string'))) {
    throw new TypeError('"labelMap" must be a Map of strings to strings.');
  }
  if(!(Array.isArray(mandatoryIndexes) &&
    mandatoryIndexes.every(Number.isInteger))) {
    throw new TypeError('"mandatoryIndexes" must be an array of integers.');
  }
}

/**
 * Decodes a Uint8Array from CBOR encoding
 * @param {Uint8Array} bytes The bytes to decode
 * @returns {Uint8Array} The decoded array
 */
function _decodeUint8Array(bytes) {
  return bytes;
}
