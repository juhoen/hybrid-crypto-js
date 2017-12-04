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


    it('keypair\'s public key shoud be object', function() {
        assert.typeOf(keypair.publicKey, 'object');
    });


    it('keypair\'s private key should be object', function() {
        assert.typeOf(keypair.privateKey, 'object');
    });


    it('should convert keys to PEMs', function() {
        var pems = keyManager.keysToPem(keypair);

        // PEMs should be object
        assert.typeOf(pems, 'object');

        // Keys should be strings
        assert.typeOf(pems.publicKey, 'string');
        assert.typeOf(pems.privateKey, 'string');
    });


    it('should convert PEMs to keys', function() {
        var pems = {
            privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\nMIIBOgIBAAJBAIfXJEy0uYHqXjRL70tgvwd+BAOG02HssGy4V/coTXu3zgKtvqcY\r\n4FKnxwVlxrZ3cpsefjzz0Dg6gMAGobUCOQUCAwEAAQJABMYDqYpkRnN08gOFGjIB\r\nJINCItmXDgbiQD/OH4pUBrfmrqrS7StlZZjv4nwVUcycPzwpppFcWOL664j3Kdpo\r\nNQIhAMRqiouNt5LElYxEP4ABwFBSI+ftpsyv/HVVOCWRzawLAiEAsQxamiUEFqSZ\r\ndPSCOgv7ts+okHLCaFOENSfmwExhyS8CIGg3M32qWw3HuqWrDJpJ05WKj7yejxMq\r\nCWTkK59bhmpTAiB+epbW+46aJmhCNtI5aYoepOaEmpbrNI6D8sdTpL1OnQIhAMGH\r\nv/xVuhoWK8FvoLz+j4NOUTwEKuOqyVCk+xN+ey+I\r\n-----END RSA PRIVATE KEY-----\r\n',
            publicKey: '-----BEGIN PUBLIC KEY-----\r\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIfXJEy0uYHqXjRL70tgvwd+BAOG02Hs\r\nsGy4V/coTXu3zgKtvqcY4FKnxwVlxrZ3cpsefjzz0Dg6gMAGobUCOQUCAwEAAQ==\r\n-----END PUBLIC KEY-----\r\n'
        }

        var keys = keyManager.pemToKeys(pems);

        // Keys should be object
        assert.typeOf(keys, 'object');

        // Keys should be objects
        assert.typeOf(keys.publicKey, 'object');
        assert.typeOf(keys.privateKey, 'object');
    })

});

describe('Crypto', function() {

    var keyManager = new KeyManager();
    var pems = {
        privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\n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\r\n-----END RSA PRIVATE KEY-----\r\n',
        publicKey: '-----BEGIN PUBLIC KEY-----\r\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1t6LreeZakBC/CdxAVKj\r\nJa0kT6E2EHGz7avKmo5P+MDqqJqHTCRgDz/Gfn2M3wBTK0JbXBKGWpOe8YEH3/CY\r\nJTLdMrPceA9AnumMvPVMOk02jlmz+eKn8zW0EUx6egF8yF1TcLVKQcxR//nbAZEY\r\n5YqRs1q6yL35s62ZY5W+ZvaaBFYMXPHMYEunrDBWwlvuyK2WRYDlKd+ELY+6OcvC\r\nJBBkT0SNwBVxz0mNXaqGrv5U9kcSES6RRJjAXd4PokDcn3kXfYps7cPDPjqLovRB\r\n46bsnDms1G4bU/mty6o2i2HJSkmjmqanSlKj2fcm3PGizML7dSTHZZSeQ2tlTmh5\r\n1QiqTwOTY9cR4sDKEP/+ylEKAvqFXFwH3uIL8SUTeUqr9JlDjIA6NVIr7pRzRdqI\r\nYKP68iFWh2Han4NFvlObfKrxI6XtqhYabRJ5CXA2cAd4zRVCDrMacz76TjbUKVPC\r\nbUIR8d+cS91qi+0By4w12SC8+c1pt6ZHWOhLH8+Rp1JThpibJVXXqj63zmGdY9j6\r\n0envsLKy9oEfGZiB8CtEFj5kHVujcufXvslLJkHj7NlZfpoqm5d/rtxELmg3aazS\r\nEi4FdF94hHnW/DasrFP1GiOTAh+0+s9y80PDQVgikpe9k1ieICgHUpM5EmWDndAU\r\nf6wE/PR/1ERPH8/ODFr3Mo0CAwEAAQ==\r\n-----END PUBLIC KEY-----\r\n'
    }
    var keypair = keyManager.pemToKeys(pems);


    it('should encrypt message', function() {
        var encrypted = crypto.encrypt(keypair, 'Hello world!');
        
        // Encrypted message should be string
        assert.typeOf(encrypted, 'string');

        // Encrypted message should contain version, iv, key and cipher
        var parsed = JSON.parse(encrypted);
        assert.typeOf(parsed.v, 'string');   // Version number
        assert.typeOf(parsed.iv, 'string');  // Initialization vector
        assert.typeOf(parsed.iv, 'string');  // AES key
        assert.typeOf(parsed.iv, 'string');  // Actual encrypted message
    });


    it('should decrypt message', function() {
        var encrypted = '{"v":"hybrid-crypto-js_0.1.0","iv":"LZQmK1oL0wMluPIMADJqdvPT/aWpQxemJ63olybtgr2U2Y5xxwm/KQfetT7gojGtEkZg3xUBRCiAMV634OQwQu2tos6+3wgILc4wVE8w+fxh8ZTs2cqnUwLNZpmYEX7lfMOpybvGujLOwwImXHOBAgtTl0UjOdmhSVCsrzzRwNDJDbhmOCmWx5scjh0N0FpisFrST84nw5Z4fimGQtFge7c6IkYPW+EdzC2n0RSkFECfmhGIOrbxiGw9etRwl917EuI+EhkhiOQ2329DSUTvhSpZnK4ceqkLBwjgr9YWVIW2UvQPfuZUA8lgvw2T9d5LzXl1EBPn1ZeZZAoytsXuXUUjM2bezlMrUXOHuSUJjGOSI1cA9ha6jc9uydgZFruh9ZDtuHV7kgHp1hIsm0GNBnxRWuVwVl62uwguGEnOtSyxrhwSqoj6xMuUrpatojJ/3fljP7dGJ/OesUXXSeI/xH/GFBr6FC7uevGPuIbTfnW4x+LU48diP6ba6uDUU6WkrgXRgAZ/52E/15cOFRxa+GnnNE6R93/01RzoeZTT+q1Wk/pdKMEDmXqsWTI/mJj/gvhraiaYuKqfoDVSiMx4I17Tdg/GgvMv6F6L/B7hfS9HfXKU7rKoTGQw0SUfGpEUz9w9NRAWXPc+/9UxPWvpM+ZTwt4KhvKIFqrPtEQkklM=","key":"JKrEPXGiT9Ujn0fjCUny0mmTBv7BGXf+7icEMMY722etT+RCLgV/+e4qvz1nLudDthlgR3dGYHu2BjMPQfCgzUdf50aeNWIrv3ZlXhUmHvQQozQscsSLc29WoM1i4p+aQx+vtIZgH1JLK8YQaheNDffPxbTMwBefiOY1JEMl+R1AN87HKLPgItIecCq4Uld2v0X3FPCAopEXkCo2AmmACxbpRZMeJ28ob3qCynDZz7cwWcHEEqiyODqt6/l2BUUQBPuI1AQ8aBn7/4PNdRAZFaNKkOScFugyG+kKM8r4xUNnCapdvMH7+0N0jH7wVP4l4BOAkzWocsSiDLUSb7e8U+xF6T12qBqc4NA4sFVntI+hKROvO+3EcH7p+x0IsTWY6R4IztSmp8tXv1PvqkFN2CiShVYPUJwI7qoYozfszb1vyZ4Uc/GDUti4WREvDC4Vfva+VRbUSPv1tGUr1X7k6/cJjK0S2Ks04aOTv9dvM6/+yBACUTPBP4gFzmI5YB79uOSRTcIzV67KZjCETe0UgAy2bRTslI7uisR+8Jvv+MRfiuAWFFqTn1KBhuW5Wyvp3oyNJeerhj7lzU80j2bQlPhu6iESrbgrIbUUSVZKnCpsSwd5FUuw9CrLMLRk25nZjLP0weHdB6pO4m2qmeDSOLO/a1SEDop7YdEscspvzX4=","cipher":"A/slOYxhxby/NbaJeSbPJw=="}';
        var decrypted = crypto.decrypt(keypair, encrypted);

        assert.typeOf(decrypted, 'string');
        assert.equal(decrypted, 'Hello world!');
    });

    it('should encrypt and decrypt simple message', function() {
        var message = 'Hello world!';
        var encrypted = crypto.encrypt(keypair, message);
        var decrypted = crypto.decrypt(keypair, encrypted);

        // Encrypted message shouldn't match with message
        assert.notEqual(encrypted, message);

        // Output should match with message
        assert.equal(decrypted, message);
    });

    it('should encrypt and decrypt message with uncommon characters', function() {
        var message = 'Ṭèßt ṃéŝŜǎg€: HẹḷȴϿ Ŵöŗľƿ!';
        var encrypted = crypto.encrypt(keypair, message);
        var decrypted = crypto.decrypt(keypair, encrypted);

        // Encrypted message shouldn't match with message
        assert.notEqual(encrypted, message);

        // Output should match with message
        assert.equal(decrypted, message);
    });

});