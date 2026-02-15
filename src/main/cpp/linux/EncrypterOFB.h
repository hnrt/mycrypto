// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTEROFB_H
#define MYCRYPTO_ENCRYPTEROFB_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterOFB
		: public Encrypter
	{
	public:

		EncrypterOFB(CipherMode cm);
		EncrypterOFB(const EncrypterOFB& src) = delete;
		virtual ~EncrypterOFB();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTEROFB_H
