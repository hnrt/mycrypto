// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCTR_H
#define MYCRYPTO_DECRYPTERCTR_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCTR
		: public Decrypter
	{
	public:

		DecrypterCTR(CipherMode cm);
		DecrypterCTR(const DecrypterCTR& src) = delete;
		virtual ~DecrypterCTR();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCTR_H
