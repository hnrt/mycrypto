package com.hideakin.mycrypto.constant;

public enum Algorithm {

	UNDEFINED(""),
	AES("AES"),
	MD5("MD5"),
	SHA1("SHA-1"),
	SHA256("SHA-256"),
	SHA384("SHA-384"),
	SHA512("SHA-512");

	private String _label;

	private Algorithm(String label) {
		_label = label;
	}

	public String label() {
		return _label;
	}

}
