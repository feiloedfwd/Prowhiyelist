	// Check whitelist
	const isWhitelisted = WHITELIST.includes(decrypted);

	// Generate proof regardless of whitelist status (anti-spoof)
	const proof = generateProof(decrypted, challenge);

	// If not whitelisted, return rejection
	if (!isWhitelisted) {
		return res.status(200).json({
			Fax: true,
			Access: false,
			Proof: proof
		});
	}

	// Generate token and encode it
	const rawToken = generateToken();
	const encodedToken = encodeToken(rawToken, decrypted);

	// Generate payload hash for extra validation
	const payloadHash = hashPayload(decrypted, true, challenge);

	return res.status(200).json({
		Fax: false,
		Access: true,
		Token: encodedToken,
		Proof: proof,
		Hash: payloadHash
	});
}
