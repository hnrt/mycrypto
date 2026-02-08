// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class DecrypterCBC
		: public Decrypter
	{
	public:

		DecrypterCBC(CipherMode cm);
		DecrypterCBC(const DecrypterCBC&) = delete;
		virtual ~DecrypterCBC();
		virtual void SetKey(void* key, void* iv);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
