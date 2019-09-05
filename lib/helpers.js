var pkg = require('../package.json');

module.exports = {
	version: () => `${pkg.name}_${pkg.version}`,
	toArray: obj => (Array.isArray(obj) ? obj : [obj]),
};
