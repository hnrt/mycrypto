// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCFB1_H
#define MYCRYPTO_ENCRYPTERCFB1_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCFB1
		: public Encrypter
	{
	public:

		EncrypterCFB1(CipherMode cm);
		EncrypterCFB1(const EncrypterCFB1& src) = delete;
		virtual ~EncrypterCFB1();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCFB1_H
