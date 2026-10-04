// api/whitelist.js - Anti-Spoof Version (CommonJS)

const CIPHER_MAP = {
	q: "a", w: "b", e: "c", r: "d", t: "e", y: "f", u: "g", i: "h", o: "i", p: "j",
	a: "k", s: "l", d: "m", f: "n", g: "o", h: "p", j: "q", k: "r", l: "s", z: "t",
	x: "u", c: "v", v: "w", b: "x", n: "y", m: "z",
	Q: "A", W: "B", E: "C", R: "D", T: "E", Y: "F", U: "G", I: "H", O: "I", P: "J",
	A: "K", S: "L", D: "M", F: "N", G: "O", H: "P", J: "Q", K: "R", L: "S", Z: "T",
	X: "U", C: "V", V: "W", B: "X", N: "Y", M: "Z",
	"5": "0", "6": "1", "7": "2", "8": "3", "9": "4",
	"0": "5", "1": "6", "2": "7", "3": "8", "4": "9"
};

const WHITELIST = [
	"NULL_99907",
	"TestUser123",
	"PremiumPlayer"
];

function decipher(encrypted) {
	let decrypted = "";
	for (let i = 0; i < encrypted.length; i++) {
		const char = encrypted[i];
		decrypted += CIPHER_MAP[char] || char;
	}
	return decrypted;
}

function cipher(str) {
	const reverseMap = {};
	for (let k in CIPHER_MAP) {
		reverseMap[CIPHER_MAP[k]] = k;
	}
	
	let ciphered = "";
	for (let i = 0; i < str.length; i++) {
		const char = str[i];
		ciphered += reverseMap[char] || char;
	}
	return ciphered;
}

function generateToken() {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let token = "";
	for (let i = 0; i < 35; i++) {
		token += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return token;
}

function encodeToken(token, username) {
	const usernameStart = username.substring(0, 3);
	const checksum = cipher(usernameStart);
	
	const mid = Math.floor(token.length / 2);
	const firstHalf = token.substring(0, mid);
	const secondHalf = token.substring(mid);
	
	const encryptedFirst = cipher(firstHalf);
	const fullToken = checksum + encryptedFirst + secondHalf;
	
	return fullToken;
}

function generateProof(username, challenge) {
	const combined = username + challenge;
	return cipher(combined);
}

function hashPayload(username, isWhitelisted, challenge) {
	const payload = username + isWhitelisted + challenge;
	let hash = 0;
	for (let i = 0; i < payload.length; i++) {
		hash += payload.charCodeAt(i);
	}
	return hash.toString(36);
}

module.exports = function handler(req, res) {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type");

	if (req.method === "OPTIONS") {
		return res.status(200).end();
	}

	if (req.method !== "POST") {
		return res.status(405).json({ error: "Method not allowed" });
	}

	try {
		const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
		const encryptedUsername = body.username;
		const challenge = body.challenge;

		if (!encryptedUsername || !challenge) {
			return res.status(400).json({
				Fax: true,
				Access: false,
				Error: "Missing username or challenge"
			});
		}

		if (challenge.length !== 32) {
			return res.status(400).json({
				Fax: true,
				Access: false,
				Error: "Invalid challenge"
			});
		}

		const decrypted = decipher(encryptedUsername);
		console.log("Decrypted username:", decrypted);

		const isWhitelisted = WHITELIST.includes(decrypted);
		const proof = generateProof(decrypted, challenge);

		if (!isWhitelisted) {
			return res.status(200).json({
				Fax: true,
				Access: false,
				Proof: proof
			});
		}

		const rawToken = generateToken();
		const encodedToken = encodeToken(rawToken, decrypted);
		const payloadHash = hashPayload(decrypted, true, challenge);

		return res.status(200).json({
			Fax: false,
			Access: true,
			Token: encodedToken,
			Proof: proof,
			Hash: payloadHash
		});

	} catch (error) {
		console.error("Error:", error);
		return res.status(500).json({
			Fax: true,
			Access: false,
			Error: error.message
		});
	}
};
