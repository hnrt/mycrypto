// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERCCM_H
#define MYCRYPTO_DECRYPTERCCM_H

#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class DecrypterCCM
		: public Decrypter
	{
	public:

		DecrypterCCM(CipherMode cm);
		DecrypterCCM(const DecrypterCCM& src) = delete;
		virtual ~DecrypterCCM();
		virtual void SetKey(void* key, void* iv, void* tag);
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);

	private:

		ByteString _aad;
		unsigned char* _buf;
		size_t _cap;
		size_t _len;
	};
}

#endif //!MYCRYPTO_DECRYPTERCCM_H
