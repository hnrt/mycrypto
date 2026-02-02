// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Cipher.h"
#include "CipherMode.h"
#include "CipherPlatform.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class Decrypter
		: public CipherPlatform
	{
	public:

		Decrypter(CipherMode cm);
		Decrypter(const Decrypter&) = delete;
		virtual ~Decrypter();
		virtual void SetKeyAndIv(void* key, void* iv);
		virtual void SetKey(void* key);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
