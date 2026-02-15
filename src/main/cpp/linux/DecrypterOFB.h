// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTEROFB_H
#define MYCRYPTO_DECRYPTEROFB_H

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterOFB
		: public Decrypter
	{
	public:

		DecrypterOFB(CipherMode cm);
		DecrypterOFB(const DecrypterOFB& src) = delete;
		virtual ~DecrypterOFB();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_DECRYPTEROFB_H
