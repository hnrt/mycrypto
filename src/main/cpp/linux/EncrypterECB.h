// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERECB_H
#define MYCRYPTO_ENCRYPTERECB_H

#include "Encrypter.h"
#include "CipherMode.h"
#include <stddef.h>

namespace hnrt
{
	class EncrypterECB
		: public Encrypter
	{
	public:

		EncrypterECB(CipherMode cm);
		EncrypterECB(const EncrypterECB& src) = delete;
		virtual ~EncrypterECB();
		virtual int GetIvLength() const;
		virtual void SetKey(void* key);
	};
}

#endif //!MYCRYPTO_ENCRYPTERECB_H
