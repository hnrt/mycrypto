// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCBC_H
#define MYCRYPTO_DECRYPTERCBC_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCBC
		: public Decrypter
	{
	public:

		DecrypterCBC(CipherMode cm);
		DecrypterCBC(const DecrypterCBC& src) = delete;
		virtual ~DecrypterCBC();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTERCBC_H
