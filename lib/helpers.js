var pkg = require('../package.json')

var helpers = {
	version: function() {
		return pkg.name + '_' + pkg.version
	}
}

module.exports = helpers