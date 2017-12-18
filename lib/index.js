var crypt = require('./crypt');
var RSA = require('./rsa');

var libs = {
	crypt: crypt,
	RSA: RSA,
}

// Include keyManager if running React Native
if (typeof navigator != 'undefined' && navigator.product == 'ReactNative') {
	var keyManager = require('./keymanager');
	libs['keyManager'] = keyManager;
}

module.exports = libs;
