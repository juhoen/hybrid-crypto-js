"use strict";

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var helpers = require('./helpers');

var forge = require('node-forge');

var pki = forge.pki;
var rsa = pki.rsa;
var AES_STANDARD = 'AES-CBC';
var DEFAULT_MD = 'sha256';

var Crypt = function () {
  function Crypt() {
    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Crypt);

    this.options = Object.assign({}, {
      md: DEFAULT_MD,
      entropy: undefined
    }, options);

    if (this.options.entropy) {
      this._entropy(this.options.entropy);
    }
  }

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
  }, {
    key: "_parseSignature",
    value: function _parseSignature(_signature) {
      try {
        return JSON.parse(_signature);
      } catch (e) {
        return {
          signature: _signature,
          md: 'sha1',
          v: helpers.version()
        };
      }
    }
  }, {
    key: "fingerprint",
    value: function fingerprint(publicKey) {
      return pki.getPublicKeyFingerprint(publicKey, {
        encoding: 'hex',
        delimiter: ':'
      });
    }
  }, {
    key: "signature",
    value: function signature(privateKey, message) {
      var checkSum = this._getMessageDigest(this.options.md);

      checkSum.update(message, 'utf8');
      if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
      var signature = privateKey.sign(checkSum);
      var signature64 = forge.util.encode64(signature);
      return JSON.stringify({
        signature: signature64,
        md: this.options.md
      });
    }
  }, {
    key: "verify",
    value: function verify(publicKey, _signature, decrypted) {
      if (!_signature) return false;

      var _this$_parseSignature = this._parseSignature(_signature),
          signature = _this$_parseSignature.signature,
          md = _this$_parseSignature.md;

      var checkSum = this._getMessageDigest(md);

      checkSum.update(decrypted, 'utf8');
      signature = forge.util.decode64(signature);
      if (typeof publicKey === 'string') publicKey = pki.publicKeyFromPem(publicKey);
      return publicKey.verify(checkSum.digest().getBytes(), signature);
    }
  }, {
    key: "encrypt",
    value: function encrypt(publicKeys, message, signature) {
      var _this = this;

      publicKeys = helpers.toArray(publicKeys);
      publicKeys = publicKeys.map(function (key) {
        return typeof key === 'string' ? pki.publicKeyFromPem(key) : key;
      });
      var iv = forge.random.getBytesSync(32);
      var key = forge.random.getBytesSync(32);
      var encryptedKeys = {};
      publicKeys.forEach(function (publicKey) {
        var encryptedKey = publicKey.encrypt(key, 'RSA-OAEP');

        var fingerprint = _this.fingerprint(publicKey);

        encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
      });
      var buffer = forge.util.createBuffer(message, 'utf8');
      var cipher = forge.cipher.createCipher(AES_STANDARD, key);
      cipher.start({
        iv: iv
      });
      cipher.update(buffer);
      cipher.finish();
      var payload = {};
      payload.v = helpers.version();
      payload.iv = forge.util.encode64(iv);
      payload.keys = encryptedKeys;
      payload.cipher = forge.util.encode64(cipher.output.data);
      payload.signature = signature;
      return JSON.stringify(payload);
    }
  }, {
    key: "decrypt",
    value: function decrypt(privateKey, encrypted) {
      this._validate(encrypted);

      var payload = JSON.parse(encrypted);
      if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
      var fingerprint = this.fingerprint(privateKey);
      var encryptedKey = payload.keys[fingerprint];
      if (!encryptedKey) throw "RSA fingerprint doesn't match with any of the encrypted message's fingerprints";
      var keyBytes = forge.util.decode64(encryptedKey);
      var iv = forge.util.decode64(payload.iv);
      var cipher = forge.util.decode64(payload.cipher);
      var key = privateKey.decrypt(keyBytes, 'RSA-OAEP');
      var buffer = forge.util.createBuffer(cipher);
      var decipher = forge.cipher.createDecipher(AES_STANDARD, key);
      decipher.start({
        iv: iv
      });
      decipher.update(buffer);
      decipher.finish();
      var bytes = decipher.output.getBytes();
      var decrypted = forge.util.decodeUtf8(bytes);
      var output = {};
      output.message = decrypted;
      output.signature = payload.signature;
      return output;
    }
  }, {
    key: "_validate",
    value: function _validate(encrypted) {
      var p = JSON.parse(encrypted);
      if (!(p.hasOwnProperty('v') && p.hasOwnProperty('iv') && p.hasOwnProperty('keys') && p.hasOwnProperty('cipher'))) throw 'Encrypted message is not valid';
    }
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