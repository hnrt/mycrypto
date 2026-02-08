// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCFB8_H
#define MYCRYPTO_ENCRYPTERCFB8_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCFB8
		: public Encrypter
	{
	public:

		EncrypterCFB8(CipherMode cm);
		EncrypterCFB8(const EncrypterCFB8& src) = delete;
		virtual ~EncrypterCFB8();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCFB8_H
