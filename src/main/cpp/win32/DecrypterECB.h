// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class DecrypterECB
		: public Decrypter
	{
	public:

		DecrypterECB(CipherMode cm);
		DecrypterECB(const DecrypterECB&) = delete;
		virtual ~DecrypterECB();
		virtual void SetKey(void* key);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
