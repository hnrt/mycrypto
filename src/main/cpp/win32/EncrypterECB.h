// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class EncrypterECB
		: public Encrypter
	{
	public:

		EncrypterECB(CipherMode cm);
		EncrypterECB(const EncrypterECB&) = delete;
		virtual ~EncrypterECB();
		virtual void SetKey(void* key);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
