// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCFB8_H
#define MYCRYPTO_DECRYPTERCFB8_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCFB8
		: public Decrypter
	{
	public:

		DecrypterCFB8(CipherMode cm);
		DecrypterCFB8(const DecrypterCFB8& src) = delete;
		virtual ~DecrypterCFB8();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCFB8_H
