function fingerprintCanvas() {
	var canvas = document.createElement('canvas');
	var ctx = canvas.getContext('2d');
	var txt = 'i9asdm..$#po((^@KbXrww!~cz';
	ctx.textBaseline = "top";
	ctx.font = "16px 'Arial'";
	ctx.textBaseline = "alphabetic";
	ctx.rotate(.05);
	ctx.fillStyle = "#f60";
	ctx.fillRect(125, 1, 62, 20);
	ctx.fillStyle = "#069";
	ctx.fillText(txt, 2, 15);
	ctx.fillStyle = "rgba(102, 200, 0, 0.7)";
	ctx.fillText(txt, 4, 17);
	ctx.shadowBlur = 10;
	ctx.shadowColor = "blue";
	ctx.fillRect(-20, 10, 234, 5);
	var strng = canvas.toDataURL();

	document.body.appendChild(canvas);

	var hash = 0;
	if (strng.length === 0) return 'nothing!';
	for (i = 0; i < strng.length; i++) {
		char = strng.charCodeAt(i);
		hash = ((hash << 5) - hash) + char;
		hash = hash & hash;
	}

	canvas.remove();

	return hash;
}

// LZW-compress a string
var Tea = {};

/**
 * Encrypts text using Corrected Block TEA (xxtea) algorithm.
 *
 * @param   {string} plaintext - String to be encrypted (multi-byte safe).
 * @param   {string} password - Password to be used for encryption (1st 16 chars).
 * @returns {string} Encrypted text (encoded as base64).
 */
Tea.encrypt = function (plaintext, password) {
	plaintext = String(plaintext);

	var k;

	if (password.constructor !== ArrayBuffer) {
		password = String(password);
		k = Tea.strToLongs(Tea.utf8Encode(password).slice(0, 16));
	} else {
		k = [4];
		var a = new Uint8Array(password);
		for (var i = 0; i < 4; i++) {
			k[i] = a[i * 4] + (a[i * 4 + 1] << 8) + (a[i * 4 + 2] << 16) + (a[i * 4 + 3] << 24);
		}
	}

	if (plaintext.length === 0) return '';  // nothing to encrypt

	//  v is n-word data vector; converted to array of longs from UTF-8 string
	var v = Tea.strToLongs(Tea.utf8Encode(plaintext));
	//  k is 4-word key; simply convert first 16 chars of password as key

	v = Tea.encode(v, k);

	// convert array of longs to string
	var ciphertext = Tea.longsToStr(v);

	// convert binary string to base64 ascii for safe transport
	return Tea.base64Encode(ciphertext);
};

/**
 * Decrypts text using Corrected Block TEA (xxtea) algorithm.
 *
 * @param   {string} ciphertext - String to be decrypted.
 * @param   {string} password - Password to be used for decryption (1st 16 chars).
 * @returns {string} Decrypted text.
 * @throws  {Error}  Invalid ciphertext
 */
Tea.decrypt = function (ciphertext, password) {
	ciphertext = String(ciphertext);
	password = String(password);

	if (ciphertext.length === 0) return '';

	//  v is n-word data vector; converted to array of longs from base64 string
	var v = Tea.strToLongs(Tea.base64Decode(ciphertext));
	//  k is 4-word key; simply convert first 16 chars of password as key
	var k = Tea.strToLongs(Tea.utf8Encode(password).slice(0, 16));

	v = Tea.decode(v, k);

	var plaintext = Tea.longsToStr(v);

	// strip trailing null chars resulting from filling 4-char blocks:
	plaintext = plaintext.replace(/\0+$/, '');

	return Tea.utf8Decode(plaintext);
};

/**
 * XXTEA: encodes array of unsigned 32-bit integers using 128-bit key.
 *
 * @param   {number[]} v - Data vector.
 * @param   {number[]} k - Key.
 * @returns {number[]} Encoded vector.
 */
Tea.encode = function (v, k) {
	if (v.length < 2) v[1] = 0;  // algorithm doesn't work for n<2 so fudge by adding a null
	var n = v.length;

	var z = v[n - 1], y = v[0], delta = 0x9e3779b9;
	var mx, e, q = Math.floor(6 + 52 / n), sum = 0;

	while (q-- > 0) {  // 6 + 52/n operations gives between 6 & 32 mixes on each word
		sum += delta;
		e = sum >>> 2 & 3;
		for (var p = 0; p < n; p++) {
			y = v[(p + 1) % n];
			mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
			z = v[p] += mx;
		}
	}

	return v;
};

/**
 * XXTEA: decodes array of unsigned 32-bit integers using 128-bit key.
 *
 * @param   {number[]} v - Data vector.
 * @param   {number[]} k - Key.
 * @returns {number[]} Decoded vector.
 */
Tea.decode = function (v, k) {
	var n = v.length;

	var z = v[n - 1], y = v[0], delta = 0x9e3779b9;
	var mx, e, q = Math.floor(6 + 52 / n), sum = q * delta;

	while (sum !== 0) {
		e = sum >>> 2 & 3;
		for (var p = n - 1; p >= 0; p--) {
			z = v[p > 0 ? p - 1 : n - 1];
			mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
			y = v[p] -= mx;
		}
		sum -= delta;
	}

	return v;
};

Tea.strToLongs = function (s) {
	// note chars must be within ISO-8859-1 (Unicode code-point <= U+00FF) to fit 4/long
	var l = new Array(Math.ceil(s.length / 4));
	for (var i = 0; i < l.length; i++) {
		// note little-endian encoding - endianness is irrelevant as long as it matches longsToStr()
		l[i] = s.charCodeAt(i * 4) + (s.charCodeAt(i * 4 + 1) << 8) +
			(s.charCodeAt(i * 4 + 2) << 16) + (s.charCodeAt(i * 4 + 3) << 24);
	} // note running off the end of the string generates nulls since bitwise operators treat NaN as 0
	return l;
};

Tea.longsToStr = function (l) {
	var str = '';
	for (var i = 0; i < l.length; i++) {
		str += String.fromCharCode(l[i] & 0xff, l[i] >>> 8 & 0xff, l[i] >>> 16 & 0xff, l[i] >>> 24 & 0xff);
	}
	return str;
};

Tea.utf8Encode = function (str) {
	return unescape(encodeURIComponent(str));
};

Tea.utf8Decode = function (utf8Str) {
	try {
		return decodeURIComponent(escape(utf8Str));
	} catch (e) {
		return utf8Str; // invalid UTF-8? return as-is
	}
};

Tea.base64Encode = function (str) {
	if (typeof btoa !== 'undefined') return btoa(str); // browser
	throw new Error('No Base64 Encode');
};

Tea.base64Decode = function (b64Str) {
	if (typeof atob === 'undefined' && typeof Buffer === 'undefined') throw new Error('No base64 decode');
	try {
		if (typeof atob !== 'undefined') return atob(b64Str); // browser
		if (typeof Buffer !== 'undefined') return new Buffer(b64Str, 'base64').toString('binary'); // Node.js
	} catch (e) {
		throw new Error('Invalid ciphertext');
	}
};

function getMimeTypes() {
	var a = [];
	for (var key in window.navigator.mimeTypes) {
		a.push({
			type: window.navigator.mimeTypes[key].type,
			suffixes: window.navigator.mimeTypes[key].suffixes,
			description: window.navigator.mimeTypes[key].description
		});
	}
	return a;
}

function getPlugins() {
	var a = [];
	for (var key in window.navigator.plugins) {
		a.push({
			description: window.navigator.plugins[key].description,
			filename: window.navigator.plugins[key].filename,
			name: window.navigator.plugins[key].name
		});
	}
	return a;
}

function getAjax(url, success) {
	var xhr = window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject('Microsoft.XMLHTTP');
	xhr.open('GET', url);
	xhr.responseType = "arraybuffer";
	xhr.onreadystatechange = function () {
		if (xhr.readyState > 3 && xhr.status === 200) success(xhr.response);
	};
	xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
	xhr.send();
	return xhr;
}

function postAjax(url, data, success) {
	var params = typeof data === 'string' ? data : Object.keys(data).map(
		function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]); }
	).join('&');

	var xhr = window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject("Microsoft.XMLHTTP");
	xhr.open('POST', url);
	xhr.responseType = "arraybuffer";
	xhr.onreadystatechange = function () {
		if (xhr.readyState > 3 && xhr.status === 200) { success(xhr.response); }
	};
	xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.send(params);
	return xhr;
}

document.onreadystatechange = function () {
	if (document.readyState === "interactive") {
		var fingerprint = {
			navigator: {
				appCodeName: window && window.navigator && window.navigator.appCodeName,
				appName: window && window.navigator && window.navigator.appName,
				appVersion: window && window.navigator && window.navigator.appVersion,
				connection: {
					effectivetype: window && window.navigator && window.navigator.connection && window.navigator.connection.effectivetype,
					rtt: window && window.navigator && window.navigator.connection &&  window.navigator.connection.rtt,
					downloadlink: window && window.navigator && window.navigator.connection &&  window.navigator.connection.downloadlink,
					saveData: window && window.navigator && window.navigator.connection &&  window.navigator.connection.saveData
				},
				oscpu: window && window.navigator && window.navigator.oscpu,
				cookieEnabled: window && window.navigator && window.navigator.cookieEnabled,
				deviceMemory: window && window.navigator && window.navigator.deviceMemory,
				doNotTrack: window && window.navigator && window.navigator.doNotTrack,
				hardwareConcurrency: window && window.navigator && window.navigator.hardwareConcurrency,
				language: window && window.navigator && window.navigator.language,
				languages: window && window.navigator && window.navigator.languages,
				maxTouchPoints: window && window.navigator && window.navigator.maxTouchPoints,
				mimeTypes: window && window.navigator && window.navigator.mimeTypes && getMimeTypes(),
				platform: window && window.navigator && window.navigator.platform,
				plugins: window && window.navigator && window.navigator.plugins && getPlugins(),
				product: window && window.navigator && window.navigator.product,
				productSub: window && window.navigator && window.navigator.productSub,
				userAgent: window && window.navigator && window.navigator.userAgent,
				vendor: window && window.navigator && window.navigator.vendor,
				vendorSub: window && window.navigator && window.navigator.vendorSub
			},
			screen: {
				availHeight: window && window.screen && window.screen.availHeight,
				availLeft: window && window.screen && window.screen.availLeft,
				availTop: window && window.screen && window.screen.availTop,
				availWidth: window && window.screen && window.screen.availWidth,
				colorDepth: window && window.screen && window.screen.colorDepth,
				height: window && window.screen && window.screen.height,
				orientation: {
					angle: window && window.screen && window.screen.orientation && window.screen.orientation.angle,
					type: window && window.screen && window.screen.orientation && window.screen.orientation.type
				},
				pixelDepth: window && window.screen && window.screen.pixelDepth,
				width: window && window.screen && window.screen.width
			},
			devicePixelRatio: window && window.devicePixelRatio,
			history: {
				length: window && window.history && window.history.length
			},
			date: {
				current: new Date(),
				offset: new Date().getTimezoneOffset(),
				local: new Date().toLocaleString()
			},
			canvas: fingerprintCanvas(),
			innerHeight: window && window.innerHeight,
			innerWidth: window && window.innerWidth,
			outerHeight: window && window.outerHeight,
			outerWidth: window && window.outerWidth,
			isFullScreen: window && window.isFullScreen,
			styleMedia: window && window.styleMedia
		};

		getAjax('/Images/Client/Security.png', function (data) {
			var password = data.slice(-16);
			var payload = Tea.encrypt(JSON.stringify(fingerprint), password);
			document.cookie = "X-Session=" + payload + '; path=/';
			//postAjax('/Security/Fingerprint', payload);
		});
	}
};

////https://github.com/Valve/fingerprintjs2/blob/master/README.md

////https://github.com/samyk/evercookie/blob/master/js/evercookie.js

////https://github.com/RD17/DeTor

////https://stackoverflow.com/questions/690025/how-to-tell-if-a-request-is-coming-from-a-proxy