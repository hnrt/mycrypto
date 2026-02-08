// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHERMODE_H
#define MYCRYPTO_CIPHERMODE_H

namespace hnrt
{
	enum CipherMode
	{
		CIPHER_UNSPECIFIED = 0,
		AES_128_ECB = 1,
		AES_192_ECB,
		AES_256_ECB,
		AES_128_CBC,
		AES_192_CBC,
		AES_256_CBC,
		AES_128_CFB1,
		AES_192_CFB1,
		AES_256_CFB1,
		AES_128_CFB8,
		AES_192_CFB8,
		AES_256_CFB8,
		AES_128_CFB128,
		AES_192_CFB128,
		AES_256_CFB128,
		AES_128_OFB,
		AES_192_OFB,
		AES_256_OFB,
		AES_128_CTR,
		AES_192_CTR,
		AES_256_CTR,
		AES_128_CCM,
		AES_192_CCM,
		AES_256_CCM,
		AES_128_GCM,
		AES_192_GCM,
		AES_256_GCM
	};

	inline bool IsCCM(CipherMode cm)
	{
		return cm == CipherMode::AES_128_CCM || cm == CipherMode::AES_192_CCM || cm == CipherMode::AES_256_CCM;
	}
}

#endif //!MYCRYPTO_CIPHERMODE_H
