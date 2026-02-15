// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCFB_H
#define MYCRYPTO_ENCRYPTERCFB_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCFB
		: public Encrypter
	{
	public:

		EncrypterCFB(CipherMode cm);
		EncrypterCFB(const EncrypterCFB& src) = delete;
		virtual ~EncrypterCFB();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCFB_H
