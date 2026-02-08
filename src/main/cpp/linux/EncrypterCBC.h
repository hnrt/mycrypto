// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCBC_H
#define MYCRYPTO_ENCRYPTERCBC_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCBC
		: public Encrypter
	{
	public:

		EncrypterCBC(CipherMode cm);
		EncrypterCBC(const EncrypterCBC& src) = delete;
		virtual ~EncrypterCBC();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCBC_H
