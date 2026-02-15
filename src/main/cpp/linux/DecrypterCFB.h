// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCFB_H
#define MYCRYPTO_DECRYPTERCFB_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCFB
		: public Decrypter
	{
	public:

		DecrypterCFB(CipherMode cm);
		DecrypterCFB(const DecrypterCFB& src) = delete;
		virtual ~DecrypterCFB();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCFB_H
