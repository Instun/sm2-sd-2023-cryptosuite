# An SM2 Selective Disclosure Data Integrity Cryptosuite _(@instun/sm2-sd-2023-cryptosuite)_

> A selective disclosure Data Integrity cryptosuite based on SM2 for use with jsonld-signatures.

## Install

```sh
npm install @instun/sm2-sd-2023-cryptosuite
```

## Basic Usage

### Creating a base proof

```javascript
import * as Sm2Multikey from '@instun/sm2-multikey';
import * as sm2Sd2023Cryptosuite from '@instun/sm2-sd-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';

// Setup key pair
const publicKeyMultibase = 'zEPJcCQ4kKGebz5ombkjw9mgikPckWeYDLhvZBzPckNsfjBa4';
const secretKeyMultibase = 'z4G1CtDVyCTyctEtfS6WD768wvhPWeN6zyMhJURHmWQwB3K4';
const controller = `did:key:${publicKeyMultibase}`;
const keyPair = await Sm2Multikey.from({
  type: 'Multikey',
  controller,
  id: `${controller}#${publicKeyMultibase}`,
  publicKeyMultibase,
  secretKeyMultibase
});

// Create and sign credential
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/data-integrity/v2'
  ],
  type: ['VerifiableCredential'],
  issuer: controller,
  issuanceDate: '2024-01-01T19:23:24Z',
  credentialSubject: {
    id: 'urn:example:123',
    name: 'John Doe'
  }
};

const suite = new DataIntegrityProof({
  signer: keyPair.signer(),
  cryptosuite: sm2Sd2023Cryptosuite.createSignCryptosuite()
});

const signedCredential = await jsigs.sign(credential, {
  suite,
  purpose: new jsigs.purposes.AssertionProofPurpose(),
  documentLoader
});
```

### Creating a derived proof

```javascript
const suite = new DataIntegrityProof({
  cryptosuite: sm2Sd2023Cryptosuite.createDiscloseCryptosuite({
    selectivePointers: ['/credentialSubject/id']
  })
});

const derivedCredential = await jsigs.derive(signedCredential, {
  suite,
  purpose: new jsigs.purposes.AssertionProofPurpose(),
  documentLoader
});
```

### Verifying a proof

```javascript
const suite = new DataIntegrityProof({
  cryptosuite: sm2Sd2023Cryptosuite.createVerifyCryptosuite()
});

const result = await jsigs.verify(derivedCredential, {
  suite,
  purpose: new jsigs.purposes.AssertionProofPurpose(),
  documentLoader
});
```

## Advanced Features

- Mandatory field disclosure
- Selective disclosure of multiple fields
- Custom document loaders
- Different proof purposes

For detailed examples of advanced usage, see our [documentation](https://github.com/instun/sm2-sd-2023-cryptosuite/wiki).

## Commercial Support

Commercial support available from Instun: support@instun.com

## License

[New BSD License (3-clause)](LICENSE) © 2024 Instun
