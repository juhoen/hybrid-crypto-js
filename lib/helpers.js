"use strict";

var pkg = require('../package.json');

module.exports = {
  version: function version() {
    return "".concat(pkg.name, "_").concat(pkg.version);
  },
  toArray: function toArray(obj) {
    return Array.isArray(obj) ? obj : [obj];
  }
};