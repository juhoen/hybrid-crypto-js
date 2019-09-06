"use strict";

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var forge = require('node-forge');

var pki = forge.pki;

var RSA =
/*#__PURE__*/
function () {
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
  /**
   * Generates RSA keypair
   *
   * @param {function} callback Function that gets called when keys are generated
   * @param {int} [keySize=4096] Integer that determines the RSA key size
   *
   * @example
   * rsa.generateKeyPair(keys => console.log(keys), 1024);
   *
   * @method
   */


  _createClass(RSA, [{
    key: "generateKeyPair",
    value: function generateKeyPair(callback, keySize) {
      // Generate key pair using forge
      pki.rsa.generateKeyPair({
        bits: keySize || this.options.keySize,
        workers: -1
      }, function (err, keyPair) {
        // Cast key pair to PEM format
        keyPair.publicKey = pki.publicKeyToPem(keyPair.publicKey);
        keyPair.privateKey = pki.privateKeyToPem(keyPair.privateKey);
        callback(keyPair);
      });
    }
    /**
     * Generates RSA keypair
     *
     * @param {int} [keySize=4096] Integer that determines the RSA key size
     *
     * @example
     * rsa.generateKeyPair(1024).then(keys => console.log(keys));
     *
     * @return {Promise} Promise that gets resolved when generation is ready
     * @method
     */

  }, {
    key: "generateKeyPairAsync",
    value: function generateKeyPairAsync(keySize) {
      var _this = this;

      return new Promise(function (resolve) {
        _this.generateKeyPair(resolve, keySize);
      });
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

  return RSA;
}();

module.exports = RSA;