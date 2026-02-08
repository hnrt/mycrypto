// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERECB_H
#define MYCRYPTO_DECRYPTERECB_H

#include "Decrypter.h"
#include "CipherMode.h"
#include <stddef.h>

namespace hnrt
{
	class DecrypterECB
		: public Decrypter
	{
	public:

		DecrypterECB(CipherMode cm);
		DecrypterECB(const DecrypterECB& src) = delete;
		virtual ~DecrypterECB();
		virtual void SetKey(void* key);
	};
}

#endif //!MYCRYPTO_DECRYPTERECB_H
