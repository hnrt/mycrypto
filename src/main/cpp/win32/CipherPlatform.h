// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include <Windows.h>
#include <stddef.h>

namespace hnrt
{
	class CipherPlatform
		: public Cipher
	{
	public:

		CipherPlatform(CipherMode cm);
		CipherPlatform(const CipherPlatform& src) = delete;
		virtual ~CipherPlatform();
		virtual void SetKey(void* key) = 0;
		virtual void SetKey(void* key, void* iv) = 0;
		virtual void SetKey(void* key, void* iv, void* aad, size_t len) = 0;
		virtual void SetKey(void* key, void* iv, void* tag) = 0;
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len) = 0;
		virtual ByteString Update(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString Finalize(void* inputBuffer, size_t inputLength) = 0;
		virtual ByteString GetTag() const;

	protected:

		LPCWSTR GetAlgorithm();
		LPCWSTR GetChainingMode();
		void SetMacContextSize();

		BCryptAlgHandle _hA;
		BCryptKeyHandle _hK;
		BCryptAuthenticatedCipherModeInfo _info;
		ByteString _iv;
	};
}
