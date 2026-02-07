// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTER_H
#define MYCRYPTO_DECRYPTER_H

#include "CipherPlatform.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class Decrypter
		: public CipherPlatform
	{
	public:

		Decrypter(CipherMode cm);
		Decrypter(const Decrypter& src) = delete;
		virtual ~Decrypter();
		virtual void SetKey(void* key);
		virtual void SetKey(void* key, void* iv);
		virtual void SetKey(void* key, void* iv, void* aad, size_t len);
		virtual void SetKey(void* key, void* iv, void* tag);
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* outputBuffer, size_t outputLength);

	private:

		ByteString _aad;
	};
}

#endif //!MYCRYPTO_DECRYPTER_H
