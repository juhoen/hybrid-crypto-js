import {AsyncStorage} from 'react-native';
var rsa = require('./rsa');

var KEYSTORE_NAME = 'keystore';
var KEYPAIR_NAME = 'keypair';
var KEY_STRING = '@' + KEYSTORE_NAME + ':' + KEYPAIR_NAME;

export default class KeyManager {

    getKeys(callback) {
        var self = this;

        function save(keys) {
            // Save just generated keys
            self.saveKeys(keys, callback);
        }

        function done(err, keys) {
            if (!keys) {
                // Generate new keys if no existing was found
                rsa.generateKeys(save);
            } else {
                // Return keys if keys was found
                callback(keys);
            }
        }

        // Try to find existing RSA keypair
        AsyncStorage.getItem(KEY_STRING, done);
    }

    saveKeys(keypair, callback) {

        var done = function(err) {
            if (callback) callback(keypair);
        }

        // Save keys in async storage
        AsyncStorage.setItem(KEY_STRING, JSON.stringify(keypair), done);
    }
}