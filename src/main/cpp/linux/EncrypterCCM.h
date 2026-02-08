// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTERCCM_H
#define MYCRYPTO_ENCRYPTERCCM_H

#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class EncrypterCCM
		: public Encrypter
	{
	public:

		EncrypterCCM(CipherMode cm);
		EncrypterCCM(const EncrypterCCM& src) = delete;
		virtual ~EncrypterCCM();
		virtual void SetKey(void* key, void* iv);
		virtual void SetKey(void* key, void* iv, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);

	private:

		void SetKeyIv(void* key, void* iv);

		ByteString _aad;
		unsigned char* _buf;
		size_t _cap;
		size_t _len;
	};
}

#endif //!MYCRYPTO_ENCRYPTERCCM_H
