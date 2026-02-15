// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCTR_H
#define MYCRYPTO_ENCRYPTERCTR_H

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCTR
		: public Encrypter
	{
	public:

		EncrypterCTR(CipherMode cm);
		EncrypterCTR(const EncrypterCTR& src) = delete;
		virtual ~EncrypterCTR();
		virtual void SetKey(void* key, void* iv);
	};
}

#endif //!MYCRYPTO_ENCRYPTERCTR_H
