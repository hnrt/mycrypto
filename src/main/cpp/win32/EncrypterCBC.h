// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class EncrypterCBC
		: public Encrypter
	{
	public:

		EncrypterCBC(CipherMode cm);
		EncrypterCBC(const EncrypterCBC&) = delete;
		virtual ~EncrypterCBC();
		virtual void SetKey(void* key, void* iv);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
