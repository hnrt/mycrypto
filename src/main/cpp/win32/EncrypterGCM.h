// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class EncrypterGCM
		: public Encrypter
	{
	public:

		EncrypterGCM(CipherMode cm);
		EncrypterGCM(const EncrypterGCM&) = delete;
		virtual ~EncrypterGCM();
		virtual void SetKey(void* key, void* iv);
		virtual void SetKey(void* key, void* iv, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
	};
}
