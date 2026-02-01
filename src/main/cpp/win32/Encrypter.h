// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include <stddef.h>

namespace hnrt
{
	class Encrypter
		: public Cipher
	{
	public:

		Encrypter(CipherMode cm);
		Encrypter(const Encrypter& src) = delete;
		virtual ~Encrypter();
		virtual void SetKeyAndIv(void* key, void* iv);
		virtual void SetAdditionalAuthenticatedData(void* ptr, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength);
		virtual ByteString GetTag();
		virtual void SetTag(void* ptr, size_t len);

	private:

		BCryptAlgHandle _hA;
		BCryptKeyHandle _hK;
		ByteString _iv;
		BCryptAuthenticatedCipherModeInfo _info;
	};
}
