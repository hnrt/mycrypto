// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCFB1_H
#define MYCRYPTO_DECRYPTERCFB1_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCFB1
		: public Decrypter
	{
	public:

		DecrypterCFB1(CipherMode cm);
		DecrypterCFB1(const DecrypterCFB1& src) = delete;
		virtual ~DecrypterCFB1();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCFB1_H
