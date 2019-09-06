"use strict";

var _crypt = _interopRequireDefault(require("./crypt"));

var _rsa = _interopRequireDefault(require("./rsa"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

window.Crypt = _crypt.default;
window.RSA = _rsa.default;