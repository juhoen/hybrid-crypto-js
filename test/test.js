'use strict';

var assert = require('chai').assert;
var should = require('chai').should();

var crypto = require('../lib/crypto');
import KeyManager from '../lib/keymanager';

describe('KeyManager', function() {

    var options = {
        saveKeys: false,
        keySize: 512,
    }

    var keyManager = new KeyManager(options);
    var keyGenerateTimeout = 2000;
    var keypair;

    // Generate keys before testing
    before(function(done) {
        keyManager.generateKeypair(function(keys) {
            keypair = keys;
            done();
        });
    });

    it('keypair should be object', function() {
        assert.typeOf(keypair, 'object');
    });

    it('keypair should contain public RSA key', function() {        
        // Keypair should have property publicKey
        keypair.should.have.property('publicKey')
    });

    it('keypair\'s public key shoud be object', function() {
        assert.typeOf(keypair.publicKey, 'object');
    });

    it('keypair should contain private RSA key', function() {
        keypair.should.have.property('privateKey');
    });

    it('keypair\'s private key should be object', function() {
        // privateKey should be object
        assert.typeOf(keypair.privateKey, 'object');
    });

    it('should convert keys to PEM', function() {
        var pems = keyManager.keysToPem(keypair);

        // PEM should be object
        assert.typeOf(pems, 'object');

        // Keys should be strings
        assert.typeOf(pems.publicKey, 'string');
        assert.typeOf(pems.privateKey, 'string');
    });

});
