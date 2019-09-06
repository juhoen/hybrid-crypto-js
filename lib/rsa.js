"use strict";

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var forge = require('node-forge');

var pki = forge.pki;

var RSA = function () {
  function RSA() {
    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, RSA);

    this.options = Object.assign({}, {
      keySize: 4096,
      rsaStandard: 'RSA-OAEP',
      entropy: undefined
    }, options);
    if (this.options.entropy) this._entropy(this.options.entropy);
  }

  _createClass(RSA, [{
    key: "generateKeyPair",
    value: function generateKeyPair(callback, keySize) {
      pki.rsa.generateKeyPair({
        bits: keySize || this.options.keySize,
        workers: -1
      }, function (err, keyPair) {
        keyPair.publicKey = pki.publicKeyToPem(keyPair.publicKey);
        keyPair.privateKey = pki.privateKeyToPem(keyPair.privateKey);
        callback(keyPair);
      });
    }
  }, {
    key: "generateKeyPairAsync",
    value: function generateKeyPairAsync(keySize) {
      var _this = this;

      return new Promise(function (resolve) {
        _this.generateKeyPair(resolve, keySize);
      });
    }
  }, {
    key: "_entropy",
    value: function _entropy(input) {
      var inputString = String(input);
      var bytes = forge.util.encodeUtf8(inputString);
      forge.random.collect(bytes);
    }
  }]);

  return RSA;
}();

module.exports = RSA;