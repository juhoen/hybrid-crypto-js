# Hybrid Crypto JS

[![NPM](https://nodei.co/npm/hybrid-crypto-js.png?compact=true)](https://nodei.co/npm/hybrid-crypto-js/)

## Introduction

<a name="introduction"></a>

*Hybrid Crypto JS* is a hybrid (RSA+AES) encryption and decryption toolkit for JavaScript. *Hybrid Crypto JS* combines RSA and AES encryption algorithms making it possible to efficiently encrypt and decrypt large messages. This cross-platform library is based on [Forge](https://github.com/digitalbazaar/forge). *Hybrid Crypto JS* can be used in browsers, Node.js or React Native.

## Documentation

<a name="documentation"></a>

**Getting started**
- [Introduction](#introduction)
- [Documentation](#documentation)
- [Installation](#installation)

**Features**
- [Initialization](#initialization)
- [Encryption](#encryption)
- [Decryption](#decryption)
- [Signatures](#signatures)
- [Verifying](#verifying)
- [RSA keypairs](#rsa-keypairs)

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
import {Crypt, RSA} from 'hybrid-crypto-js';
```

**Web**

Download minified *hybrid-crypto.min.js* file [here](https://raw.githubusercontent.com/juhoen/hybrid-crypto-js/master/web/hybrid-crypto.min.js).
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
var entropy = "Random string, integer or float";
var crypt = new Crypt({entropy: entropy});
var rsa = new RSA({entropy: entropy});
```

### Encryption

<a name="encryption"></a>

*Hybrid Crypto JS* provides basic encryption function which supports also multiple RSA keys, with or without [signature](#signatures). Encrypted message is outputted as a JSON string.

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

Decrypting message with *Hybrid Crypto JS* is as easy as encrypting. Decryption function can decrypt any message which has been encrypted with keypair's public key. Decrypted message is outputted as a JSON object.

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

*Hybrid Crypto JS* provides simple message signing. When issuer signs a message, message receiver can be sure of the message issuer.

```js
var message = 'Hello world!';

// Create a signature with ISSUER's private RSA key
var signature = crypt.signature(issuerPrivateKey, message);

// Encrypt message with RECEIVERS public RSA key and attach the signature
var encrypted = crypt.encrypt(receiverPublicKey, message, signature);
```

### Verifying

<a name="verifying"></a>

Message receiver needs to have message issuer's public RSA key in order to verify message issuer.

```js
// Encrypted message with signature
var encrypted = '{"v":"hybri... ..."signature":"sdL93kfd...';

// Decrypt message with own (RECEIVER) private key
var decrypted = crypt.decrypt(receiverPrivateKey, encrypted);

// Verify message with ISSUER's public key
var verified = crypt.verify(issuerPublicKey, decrypted.signature, decrypted.message);
```
Verification function return *true* or *false* depending on whether the verification was successfull.

### RSA keypairs

<a name="rsa-keypairs"></a>

*Hybrid Crypto JS* RSA key generation function is based in [Forge](https://github.com/digitalbazaar/forge#rsa) key pair generation function. As a difference *Hybrid Crypto JS* returns keypair in PEM format.

```js
// Initialize RSA-class
var rsa = new RSA();

// Generate RSA key pair, defaults on 4096 bit key
rsa.generateKeypair(function(keypair) {

    // Callback function receives new keypair as a first argument
    var publicKey = keypair.publicKey;
    var privateKey = keypair.privateKey;
});

// Generate 1024 bit RSA key pair
rsa.generateKeypair(function(keypair) {

    // Callback function receives new 1024 bit keypair as an argument
    var publicKey = keypair.publicKey;
    var privateKey = keypair.privateKey;
}, 1024);  // Key size

// RSA can be also initialized with options
var rsa = new RSA({
    keySize: 4096, 
    rsaStandard: 'RSA-OAEP'  // RSA-OAEP or RSAES-PKCS1-V1_5, 
});

```
