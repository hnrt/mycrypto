// Copyright (C) 2026 Hideaki Narita

#pragma once

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

		Decrypter(const Decrypter&) = delete;
		virtual ~Decrypter();
		virtual void SetKey(void* key);
		virtual void SetKey(void* key, void* iv);
		virtual void SetKey(void* key, void* iv, void* aad, size_t len);
		virtual void SetKey(void* key, void* iv, void* tag);
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
		virtual ByteString GetTag() const;

	protected:

		Decrypter(CipherMode cm);
		ByteString UpdateAEAD(void* inputBuffer, size_t inputLength);
		ByteString FinalizeAEAD(void* inputBuffer, size_t inputLength);

		static ByteString RemovePadding(const ByteString& bs);
	};
}
