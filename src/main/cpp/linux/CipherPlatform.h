// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHERPLATFORM_H
#define MYCRYPTO_CIPHERPLATFORM_H

#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include <openssl/evp.h>
#include <stddef.h>

namespace hnrt
{
	class CipherPlatform
		: public Cipher
	{
	public:

		CipherPlatform(CipherMode cm);
		CipherPlatform(const CipherPlatform& src) = delete;
		virtual ~CipherPlatform();
		virtual void SetKey(void* key) = 0;
		virtual void SetKey(void* key, void* iv) = 0;
		virtual void SetKey(void* key, void* iv, void* aad, size_t len) = 0;
		virtual void SetKey(void* key, void* iv, void* tag) = 0;
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len) = 0;
		virtual ByteString Update(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString GetTag() const;

	protected:

		static String ErrorMessage();

		const EVP_CIPHER* GetAlgorithm();

		EVP_CIPHER_CTX* _ctx;
	};
}

#endif //!MYCRYPTO_CIPHERPLATFORM_H
