var Crypt = require('./crypt');
var RSA = require('./rsa');

var libs = {
    Crypt: Crypt,
    RSA: RSA,
};

// Include keyManager if running React Native
if (typeof navigator != 'undefined' && navigator.product == 'ReactNative') {
    var keyManager = require('./keymanager');
    libs['keyManager'] = keyManager;
}

module.exports = libs;
