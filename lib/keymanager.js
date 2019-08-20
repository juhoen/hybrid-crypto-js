import { AsyncStorage } from 'react-native';
import RSA from './rsa';

var KEYSTORE_NAME = 'keystore';
var KEYPAIR_NAME = 'keypair';
var KEY_STRING = '@' + KEYSTORE_NAME + ':' + KEYPAIR_NAME;

var rsa = new RSA();

var keyManager = {
    getKeys: function(callback) {
        function save(keys) {
            // Save just generated keys
            keyManager.saveKeys(keys, callback);
        }

        function done(err, keys) {
            if (!keys) {
                // Generate new keys if no existing was found
                rsa.generateKeypair(save);
            } else {
                // Return keys if keys was found
                callback(keys);
            }
        }

        // Try to find existing RSA keypair
        AsyncStorage.getItem(KEY_STRING, done);
    },

    saveKeys: function(keypair, callback) {
        var done = function(err) {
            if (callback) callback(keypair);
        };

        // Save keys in async storage
        AsyncStorage.setItem(KEY_STRING, JSON.stringify(keypair), done);
    },
};

module.exports = keyManager;
