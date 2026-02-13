// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHERMODE_H
#define MYCRYPTO_CIPHERMODE_H

namespace hnrt
{
	enum CipherMode
	{
		CIPHER_UNSPECIFIED = 0,
#define AES_VAL(j,k) ((j)*256+(k))
		AES_START = AES_VAL(1, 0),
		AES_128_ECB = AES_VAL(2, 16),
		AES_192_ECB = AES_VAL(2, 24),
		AES_256_ECB = AES_VAL(2, 32),
		AES_128_CBC = AES_VAL(3, 16),
		AES_192_CBC = AES_VAL(3, 24),
		AES_256_CBC = AES_VAL(3, 32),
		AES_128_CFB1 = AES_VAL(4, 16),
		AES_192_CFB1 = AES_VAL(4, 24),
		AES_256_CFB1 = AES_VAL(4, 32),
		AES_128_CFB8 = AES_VAL(5, 16),
		AES_192_CFB8 = AES_VAL(5, 24),
		AES_256_CFB8 = AES_VAL(5, 32),
		AES_128_CFB128 = AES_VAL(6, 16),
		AES_192_CFB128 = AES_VAL(6, 24),
		AES_256_CFB128 = AES_VAL(6, 32),
		AES_128_OFB = AES_VAL(7, 16),
		AES_192_OFB = AES_VAL(7, 24),
		AES_256_OFB = AES_VAL(7, 32),
		AES_128_CTR = AES_VAL(8, 16),
		AES_192_CTR = AES_VAL(8, 24),
		AES_256_CTR = AES_VAL(8, 32),
		AES_128_CCM = AES_VAL(9, 16),
		AES_192_CCM = AES_VAL(9, 24),
		AES_256_CCM = AES_VAL(9, 32),
		AES_128_GCM = AES_VAL(10, 16),
		AES_192_GCM = AES_VAL(10, 24),
		AES_256_GCM = AES_VAL(10, 32),
		AES_END = AES_VAL(11, 0)
#undef AES_VAL
	};

	inline bool IsAES(CipherMode cm)
	{
		return AES_START <= cm && cm <= AES_END;
	}

	inline int CipherModeToKeyLength(CipherMode cm)
	{
		return IsAES(cm) ? (cm % 256) : 0;
	}
}

#endif //!MYCRYPTO_CIPHERMODE_H
