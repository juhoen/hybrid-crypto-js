"use strict";

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(source, true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(source).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var helpers = require('./helpers');

var forge = require('node-forge');

var pki = forge.pki,
    rsa = forge.rsa;

var _require = require('./constants'),
    DEFAULT_MESSAGE_DIGEST = _require.DEFAULT_MESSAGE_DIGEST,
    DEFAULT_AES_KEY_SIZE = _require.DEFAULT_AES_KEY_SIZE,
    DEFAULT_AES_IV_SIZE = _require.DEFAULT_AES_IV_SIZE,
    AES_STANDARD = _require.AES_STANDARD,
    RSA_STANDARD = _require.RSA_STANDARD;

var Crypt =
/*#__PURE__*/
function () {
  function Crypt() {
    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Crypt);

    this.options = _objectSpread({
      md: DEFAULT_MESSAGE_DIGEST,
      aesKeySize: DEFAULT_AES_KEY_SIZE,
      aesIvSize: DEFAULT_AES_IV_SIZE,
      aesStandard: AES_STANDARD,
      rsaStandard: RSA_STANDARD,
      entropy: undefined
    }, options); // Add some entropy if available

    if (this.options.entropy) {
      this._entropy(this.options.entropy);
    }
  }
  /**
   * Returns message digest by type
   *
   * @param {String} messageDigest Message digest type as string
   *
   * @return {Object} Initialized message digest
   * @method
   */


  _createClass(Crypt, [{
    key: "_getMessageDigest",
    value: function _getMessageDigest(messageDigest) {
      switch (messageDigest) {
        case 'sha1':
          return forge.md.sha1.create();

        case 'sha256':
          return forge.md.sha256.create();

        case 'sha384':
          return forge.md.sha384.create();

        case 'sha512':
          return forge.md.sha512.create();

        case 'md5':
          return forge.md.md5.create();

        default:
          console.warn("Message digest \"".concat(this.options.md, "\" not found. Using default message digest \"sha1\" instead"));
          return forge.md.sha1.create();
      }
    }
    /**
     * Parses hybrid-crypto-js signature
     *
     * @param {String} _signature Signature string. Either JSON formatted string (>= hybrid-crypto-js 0.2.1) or plain signature
     *
     * @return {Object} Parsed signature
     * @method
     */

  }, {
    key: "_parseSignature",
    value: function _parseSignature(_signature) {
      // Try parsing signature string. This works if
      // signature is generated with hybrid-crypto-js
      // versions >= 0.2.1.
      try {
        return JSON.parse(_signature);
      } catch (e) {
        // Fallback to old signature type. This works
        // with signatures generated with hybrid-cryto-js
        // versions <= 0.2.0
        return {
          signature: _signature,
          md: 'sha1',
          v: helpers.version()
        };
      }
    }
    /**
     * Returns fingerprint for any public key
     *
     * @param {Object} publicKey Forge public key object
     *
     * @return {String} Public key's fingerprint
     * @method
     */

  }, {
    key: "fingerprint",
    value: function fingerprint(publicKey) {
      return pki.getPublicKeyFingerprint(publicKey, {
        encoding: 'hex',
        delimiter: ':'
      });
    }
    /**
     * Signs a message
     *
     * @param {String} privateKey Private key in PEM format
     * @param {String} message Message to sign
     *
     * @return {String} Signature and meta data as a JSON formatted string
     * @method
     */

  }, {
    key: "signature",
    value: function signature(privateKey, message) {
      // Create SHA-1 checksum
      var checkSum = this._getMessageDigest(this.options.md);

      checkSum.update(message, 'utf8'); // Accept both PEMs and forge private key objects

      if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
      var signature = privateKey.sign(checkSum);
      var signature64 = forge.util.encode64(signature); // Return signature in JSON format

      return JSON.stringify({
        signature: signature64,
        md: this.options.md
      });
    }
    /**
     * Verifies a message
     *
     * @param {String} publicKey Public key in PEM format
     * @param {String} _signature Signature in JSON string format
     * @param {String} decrypted Decrypted message
     *
     * @return {Boolean} Tells whether verification were successful or not
     * @method
     */

  }, {
    key: "verify",
    value: function verify(publicKey, _signature, decrypted) {
      // Return false if no signature is defined
      if (!_signature) return false; // Parse signature object into actual signature and message digest type

      var _this$_parseSignature = this._parseSignature(_signature),
          signature = _this$_parseSignature.signature,
          md = _this$_parseSignature.md; // Create SHA-1 checksum


      var checkSum = this._getMessageDigest(md);

      checkSum.update(decrypted, 'utf8'); // Base64 decode signature

      signature = forge.util.decode64(signature); // Accept both PEMs and forge private key objects

      if (typeof publicKey === 'string') publicKey = pki.publicKeyFromPem(publicKey); // Verify signature

      return publicKey.verify(checkSum.digest().getBytes(), signature);
    }
    /**
     * Encrypts a message using public RSA key and optional signature
     *
     * @param {String[]} publicKeys Public keys in PEM format
     * @param {String} message Message to encrypt
     * @param {String} signature Optional signature
     *
     * @return {String} Encrypted message and metadata as a JSON formatted string
     * @method
     */

  }, {
    key: "encrypt",
    value: function encrypt(publicKeys, message, signature) {
      var _this = this;

      // Generate flat array of keys
      publicKeys = helpers.toArray(publicKeys); // Map PEM keys to forge public key objects

      publicKeys = publicKeys.map(function (key) {
        return typeof key === 'string' ? pki.publicKeyFromPem(key) : key;
      }); // Generate random keys

      var iv = forge.random.getBytesSync(this.options.aesIvSize);
      var key = forge.random.getBytesSync(this.options.aesKeySize / 8); // Encrypt random key with all of the public keys

      var encryptedKeys = {};
      publicKeys.forEach(function (publicKey) {
        var encryptedKey = publicKey.encrypt(key, _this.options.rsaStandard);

        var fingerprint = _this.fingerprint(publicKey);

        encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
      }); // Create buffer and cipher

      var buffer = forge.util.createBuffer(message, 'utf8');
      var cipher = forge.cipher.createCipher(this.options.aesStandard, key); // Actual encryption

      cipher.start({
        iv: iv
      });
      cipher.update(buffer);
      cipher.finish(); // Attach encrypted message int payload

      var payload = {};
      payload.v = helpers.version();
      payload.iv = forge.util.encode64(iv);
      payload.keys = encryptedKeys;
      payload.cipher = forge.util.encode64(cipher.output.data);
      payload.signature = signature;
      payload.tag = cipher.mode.tag && forge.util.encode64(cipher.mode.tag.getBytes()); // Return encrypted message

      return JSON.stringify(payload);
    }
    /**
     * Decrypts a message using private RSA key
     *
     * @param {String} privateKey Private key in PEM format
     * @param {String} encrypted Message to decrypt
     *
     * @return {Object} Decrypted message and metadata as a JSON object
     * @method
     */

  }, {
    key: "decrypt",
    value: function decrypt(privateKey, encrypted) {
      // Validate encrypted message
      this._validate(encrypted); // Parse encrypted string to JSON


      var payload = JSON.parse(encrypted); // Accept both PEMs and forge private key objects
      // Cast PEM to forge private key object

      if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey); // Get key fingerprint

      var fingerprint = this.fingerprint(privateKey); // Get encrypted keys and encrypted message from the payload

      var encryptedKey = payload.keys[fingerprint]; // Log error if key wasn't found

      if (!encryptedKey) throw "RSA fingerprint doesn't match with any of the encrypted message's fingerprints"; // Get bytes of encrypted AES key, initialization vector and cipher

      var keyBytes = forge.util.decode64(encryptedKey);
      var iv = forge.util.decode64(payload.iv);
      var cipher = forge.util.decode64(payload.cipher);
      var tag = payload.tag && forge.util.decode64(payload.tag); // Use RSA to decrypt AES key

      var key = privateKey.decrypt(keyBytes, this.options.rsaStandard); // Create buffer and decipher

      var buffer = forge.util.createBuffer(cipher);
      var decipher = forge.cipher.createDecipher(this.options.aesStandard, key); // Actual decryption

      decipher.start({
        iv: iv,
        tag: tag
      });
      decipher.update(buffer);
      decipher.finish(); // Return utf-8 encoded bytes

      var bytes = decipher.output.getBytes();
      var decrypted = forge.util.decodeUtf8(bytes);
      var output = {};
      output.message = decrypted;
      output.signature = payload.signature;
      return output;
    }
    /**
     * Validates encrypted message
     *
     * @param {String} encrypted Encrypted message
     *
     * @method
     */

  }, {
    key: "_validate",
    value: function _validate(encrypted) {
      var p = JSON.parse(encrypted);
      if ( // Check required properties
      !(p.hasOwnProperty('v') && p.hasOwnProperty('iv') && p.hasOwnProperty('keys') && p.hasOwnProperty('cipher'))) throw 'Encrypted message is not valid';
    }
    /**
     * Private function to add more entropy
     *
     * @param {String|Number} input Something random
     *
     * @method
     */

  }, {
    key: "_entropy",
    value: function _entropy(input) {
      var inputString = String(input);
      var bytes = forge.util.encodeUtf8(inputString);
      forge.random.collect(bytes);
    }
  }]);

  return Crypt;
}();

module.exports = Crypt;