package com.hideakin.mycrypto.constant;

public enum CipherMode {

	UNDEFINED("", "", false, false),
	CBC("CBC", "Cipher Block Chaining", true, false),
	ECB("ECB", "Electronic CodeBook", false, false),
	CFB("CFB", "128-bit Cipher FeedBack Mode", true, false),
	CFB8("CFB8", "8-bit Cipher FeedBack Mode", true, false),
	OFB("OFB", "128-bit Output FeedBack Mode", true, false),
	OFB8("OFB8", "8-bit Output FeedBack Mode", true, false),
	CTR("CTR", "Counter Mode", true, false),
	GCM("GCM", "Galois/Counter Mode", false, true);

	private String _label;
	private String _description;
	private boolean _useIV;
	private boolean _useNonce;

	private CipherMode(String label, String description, boolean useIV, boolean useNonce) {
		_label = label;
		_description = description;
		_useIV = useIV;
		_useNonce = useNonce;
	}

	public String label() {
		return _label;
	}

	public String description() {
		return _description;
	}

	public boolean useIV() {
		return _useIV;
	}

	public boolean useNonce() {
		return _useNonce;
	}

}
