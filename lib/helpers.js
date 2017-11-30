
after = function(times, func) {
	return function() {
		times += 1;
		if (times < 1) {
			return func.apply(this, arguments);
		}
	};
};