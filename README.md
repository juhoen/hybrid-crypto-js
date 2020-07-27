# Hybrid Crypto JS

[![NPM](https://nodei.co/npm/hybrid-crypto-js.png)](https://nodei.co/npm/hybrid-crypto-js/)

## Introduction

<a name="introduction"></a>

_Hybrid Crypto JS_ is a hybrid (RSA+AES) encryption and decryption toolkit for JavaScript. _Hybrid Crypto JS_ combines RSA and AES encryption algorithms, making it possible to encrypt and decrypt large messages efficiently. This cross-platform library is based on [Forge](https://github.com/digitalbazaar/forge). _Hybrid Crypto JS_ can be used in browsers, Node.js, or React Native.

## Documentation

<a name="documentation"></a>

**Getting started**

-   [Introduction](#introduction)
-   [Documentation](#documentation)
-   [Installation](#installation)

**Features**

-   [Initialization](#initialization)
-   [Encryption](#encryption)
-   [Decryption](#decryption)
-   [Signatures](#signatures)
-   [Verifying](#verifying)
-   [RSA key pairs](#rsa-key-pairs)

### Installation

<a name="installation"></a>

```
npm install hybrid-crypto-js
```

### Importing

**Node.js**

```js
var RSA = require('hybrid-crypto-js').RSA;
var Crypt = require('hybrid-crypto-js').Crypt;
```

**React Native**

```js
import { Crypt, RSA } from 'hybrid-crypto-js';
```

**Web**

Download minified _hybrid-crypto.min.js_ file [here](https://raw.githubusercontent.com/juhoen/hybrid-crypto-js/master/web/hybrid-crypto.min.js).

```html
<script type="text/javascript" src="hybrid-crypto.min.js"></script>
```

## Features

### Initialization

<a name="initialization"></a>

```js
// Basic initialization
var crypt = new Crypt();
var rsa = new RSA();

// Increase amount of entropy
var entropy = 'Random string, integer or float';
var crypt = new Crypt({ entropy: entropy });
var rsa = new RSA({ entropy: entropy });

// Select default message digest
var crypt = new Crypt({ md: 'sha512' });

// Select AES or RSA standard
var crypt = new Crypt({
    // Default AES standard is AES-CBC. Options are:
    // AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-GCM, 3DES-ECB, 3DES-CBC, DES-ECB, DES-CBC
    aesStandard: 'AES-CBC',
    // Default RSA standard is RSA-OAEP. Options are:
    // RSA-OAEP, RSAES-PKCS1-V1_5
    rsaStandard: 'RSA-OAEP',
});

// Alternate AES keysize (some AES algorithms requires specific key size)
var crypt = new Crypt({
    aesKeySize: 192, // Defaults to 256
});
```

### Encryption

<a name="encryption"></a>

_Hybrid Crypto JS_ provides basic encryption function that also supports multiple RSA keys, with or without [signature](#signatures). An encrypted message is a JSON formatted string.

```js
var message = 'Hello world!';

// Encryption with one public RSA key
var encrypted = crypt.encrypt(publicKey, message);

// Function also supports encryption with multiple RSA public keys
var encrypted = crypt.encrypt([publicKey1, publicKey2, publicKey3], message);

// Encryption with signature
var encrypted = crypt.encrypt(publicKey, message, signature);
```

**Pretty-printed sample output**

```js
{
    "v": "hybrid-crypto-js_0.1.2",        // Current package version
    "iv": "CmtyaZTyzoAp1mTNUTztic0v1...", // Initialization vector
    "keys": {                             // Encrypted AES keys by RSA fingerprints
        "85:3d:10:e1:56...": "bHaTF9...",
        "d3:48:6a:e9:13...": "t9eds3..."
    },
    "cipher": "+iwVFsC2dECBQvwcm9DND..."  // Actual encrypted message
    "signature": "sdL93kfdm12feds3C2..."  // Signature (optional)
}

```

### Decryption

<a name="decryption"></a>

Decrypting message with _Hybrid Crypto JS_ is as easy as encrypting. Decrypt function can decrypt any message which has been encrypted with key pair's public key. The decrypted message is a JSON object containing a message and an optional signature.

```js
var encrypted = '{"v":"hybrid-crypto-js_0.1.0","iv":"CmtyaZTyzoAp1mTN...';

// Decrypt encryped message with private RSA key
var decrypted = crypt.decrypt(privateKey, encrypted);

// Get decrypted message
var message = decrypted.message;
```

**Sample output**

```js
{
    message: "Hello world!",            // Actual decrypted message
    signature: "sdL93kfdm12feds3C2..."  // Signature (optional)
}
```

### Signatures

<a name="signatures"></a>

_Hybrid Crypto JS_ provides simple message signing. The encrypted message can be signed with the issuer's private key.

```js
var message = 'Hello world!';

// Create a signature with ISSUER's private RSA key
var signature = crypt.signature(issuerPrivateKey, message);

// Encrypt message with RECEIVERS public RSA key and attach the signature
var encrypted = crypt.encrypt(receiverPublicKey, message, signature);

// Select default message digest
var crypt = new Crypt({
    md: 'sha512', // Options: sha1, sha256, sha384, sha512, and md5
});
```

### Verifying

<a name="verifying"></a>

The message receiver needs to have a message issuer's public RSA key in order to verify the message issuer.

```js
// Encrypted message with signature
var encrypted = '{"v":"hybri... ..."signature":"sdL93kfd...';

// Decrypt message with own (RECEIVER) private key
var decrypted = crypt.decrypt(receiverPrivateKey, encrypted);

// Verify message with ISSUER's public key
var verified = crypt.verify(
    issuerPublicKey,
    decrypted.signature,
    decrypted.message,
);
```

Verification function returns _true_ or _false_ depending on whether the verification was successful.

### RSA key pairs

<a name="rsa-key-pairs"></a>

_Hybrid Crypto JS_ RSA key generation function is based in [Forge](https://github.com/digitalbazaar/forge#rsa) key pair generation function. As a difference, _Hybrid Crypto JS_ returns key pair in PEM format.

```js
// Initialize RSA-class
var rsa = new RSA();

// Generate RSA key pair, default key size is 4096 bit
rsa.generateKeyPair(function(keyPair) {
    // Callback function receives new key pair as a first argument
    var publicKey = keyPair.publicKey;
    var privateKey = keyPair.privateKey;
});

// ... or:
rsa.generateKeyPairAsync().then(keyPair => {
    var publicKey = keyPair.publicKey;
    var privateKey = keyPair.privateKey;
});

// Generate 1024 bit RSA key pair
rsa.generateKeyPair(function(keyPair) {
    // Callback function receives new 1024 bit key pair as a first argument
    var publicKey = keyPair.publicKey;
    var privateKey = keyPair.privateKey;
}, 1024); // Key size

// RSA can be also initialized with options
var rsa = new RSA({
    keySize: 4096,
});
```
