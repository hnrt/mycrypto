// Copyright (C) 2026 Hideaki Narita

#pragma once

#include <Windows.h>
#include <bcrypt.h>

namespace hnrt
{
	class BCryptKeyHandle;

	class BCryptAuthenticatedCipherModeInfo
		: public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
	{
	public:

		BCryptAuthenticatedCipherModeInfo();
		BCryptAuthenticatedCipherModeInfo(const BCryptAuthenticatedCipherModeInfo&);
		~BCryptAuthenticatedCipherModeInfo();
		BCryptAuthenticatedCipherModeInfo& operator =(const BCryptAuthenticatedCipherModeInfo&);
		BCryptAuthenticatedCipherModeInfo& SetNonce(const void*, size_t);
		BCryptAuthenticatedCipherModeInfo& SetAuthDataSize(size_t);
		BCryptAuthenticatedCipherModeInfo& SetAuthData(const void*, size_t);
		BCryptAuthenticatedCipherModeInfo& SetTagSize(size_t);
		BCryptAuthenticatedCipherModeInfo& SetTag(const void*, size_t);
		BCryptAuthenticatedCipherModeInfo& SetMacContextSize(size_t);
		BCryptAuthenticatedCipherModeInfo& SetDataSize(size_t);
		BCryptAuthenticatedCipherModeInfo& SetFlags(ULONG);
		BCryptAuthenticatedCipherModeInfo& ResetFlags(ULONG);
	};
}
