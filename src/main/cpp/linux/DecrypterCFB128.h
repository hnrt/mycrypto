// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCFB128_H
#define MYCRYPTO_DECRYPTERCFB128_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCFB128
		: public Decrypter
	{
	public:

		DecrypterCFB128(CipherMode cm);
		DecrypterCFB128(const DecrypterCFB128& src) = delete;
		virtual ~DecrypterCFB128();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCFB128_H
