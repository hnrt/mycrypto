// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ENCRYPTER_H
#define MYCRYPTO_ENCRYPTER_H

#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <openssl/evp.h>
#include <stddef.h>

namespace hnrt
{
	class Encrypter
		: public Cipher
	{
	public:

		Encrypter(CipherMode cm);
		Encrypter(const Encrypter& src) = delete;
		virtual ~Encrypter();
		virtual void SetKeyAndIv(void* key, void* iv);
		virtual void SetAdditionalAuthenticatedData(void* ptr, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* outputBuffer, size_t outputLength);
		virtual ByteString GetTag();
		virtual void SetTag(void* ptr, size_t len);

	private:

		EVP_CIPHER_CTX* _ctx;
	};
}

#endif //!MYCRYPTO_ENCRYPTER_H
