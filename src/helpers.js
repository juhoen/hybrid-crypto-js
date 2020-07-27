// @flow
var pkg = require('../package.json');

module.exports = {
    version: () => `${pkg.name}_${pkg.version}`,
    toArray: (obj: Object) => (Array.isArray(obj) ? obj : [obj]),
};
