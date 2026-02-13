// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHER_H
#define MYCRYPTO_CIPHER_H

#include "CipherMode.h"
#include "OperationMode.h"
#include "ByteString.h"
#include <stddef.h>

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
		virtual int GetNonceLength() const;
		virtual void SetNonceLength(int len);
		virtual int GetTagLength() const;
		virtual void SetTagLength(int len);
		virtual void SetKey(void* key) = 0;
		virtual void SetKey(void* key, void* iv) = 0;
		virtual void SetKey(void* key, void* iv, void* aad, size_t len) = 0;
		virtual void SetKey(void* key, void* iv, void* tag) = 0;
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len) = 0;
		virtual ByteString Update(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString GetTag() const = 0;

		static Cipher* CreateInstance(CipherMode cm, OperationMode om);

	protected:

		Cipher(CipherMode cm);

		int _r;
		CipherMode _cm;
	};
}

#endif //!MYCRYPTO_CIPHER_H
