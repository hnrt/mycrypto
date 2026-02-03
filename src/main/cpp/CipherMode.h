// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHERMODE_H
#define MYCRYPTO_CIPHERMODE_H

namespace hnrt
{
	enum CipherMode
	{
		CIPHER_UNSPECIFIED = 0,
		AES_128_CBC = 1,
		AES_192_CBC,
		AES_256_CBC,
		AES_128_ECB,
		AES_192_ECB,
		AES_256_ECB,
		AES_128_CFB,
		AES_192_CFB,
		AES_256_CFB,
		AES_128_GCM,
		AES_192_GCM,
		AES_256_GCM,
		AES_128_CCM,
		AES_192_CCM,
		AES_256_CCM
	};
}

#endif //!MYCRYPTO_CIPHERMODE_H
