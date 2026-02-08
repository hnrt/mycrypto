// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCFB128_H
#define MYCRYPTO_ENCRYPTERCFB128_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCFB128
		: public Encrypter
	{
	public:

		EncrypterCFB128(CipherMode cm);
		EncrypterCFB128(const EncrypterCFB128& src) = delete;
		virtual ~EncrypterCFB128();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCFB128_H
