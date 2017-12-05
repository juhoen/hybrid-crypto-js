var pkg = require('../package.json');

var helpers = {
	version: function() {
		return pkg.name + '_' + pkg.version;
	},

	toArray: function(obj) {
		if (Array.isArray(obj)) return obj
		return [obj]
	}
}

module.exports = helpers;