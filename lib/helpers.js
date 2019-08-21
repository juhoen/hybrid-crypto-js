var pkg = require('../package.json');

var helpers = {
    version: () => `${pkg.name}_${pkg.version}`,
    toArray: obj => (Array.isArray(obj) ? obj : [obj]),
};

module.exports = helpers;
