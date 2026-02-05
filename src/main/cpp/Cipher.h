// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHER_H
#define MYCRYPTO_CIPHER_H

#include "CipherMode.h"
#include "OperationMode.h"
#include "ByteString.h"
#include <stddef.h>

#define AES_BLOCK_LENGTH 16

#define AES_128_KEY_LENGTH 16
#define AES_192_KEY_LENGTH 24
#define AES_256_KEY_LENGTH 32

#define CCM_IV_LENGTH 12
#define CCM_TAG_LENGTH 16

#define GCM_IV_LENGTH 12
#define GCM_TAG_LENGTH 16

namespace hnrt
{
	class Cipher
	{
	public:

		Cipher(const Cipher& src) = delete;
		virtual ~Cipher();
		virtual Cipher* AddRef();
		virtual void Release();
		virtual int GetKeyLength() const;
		virtual int GetIvLength() const;
		virtual int GetTagLength() const;
		virtual void SetKeyAndIv(void* key, void* iv) = 0;
		virtual void SetKey(void* key) = 0;
		virtual void SetPayloadLength(size_t len) = 0;
		virtual void SetAdditionalAuthenticatedData(void* ptr, size_t len) = 0;
		virtual ByteString Update(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString GetTag() = 0;
		virtual void SetTag(void* ptr, size_t len) = 0;

		static Cipher* CreateInstance(CipherMode cm, OperationMode om);

	protected:

		Cipher(CipherMode cm);

		int _r;
		CipherMode _cm;
	};
}

#endif //!MYCRYPTO_CIPHER_H
