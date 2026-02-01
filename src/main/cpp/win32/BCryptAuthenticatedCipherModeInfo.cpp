// Copyright (C) 2026 Hideaki Narita


#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Heap.h"
#include <Windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>


#define COPY_PUCHAR_MEMBER(x,y,z) Copy(x, y, z.x, z.y)


using namespace hnrt;


static void Copy(unsigned char*& pbDst, ULONG& cbDst, const unsigned char* pbSrc, ULONG cbSrc)
{
	if (pbSrc && cbSrc)
	{
		pbDst = reinterpret_cast<unsigned char*>(Allocate(cbSrc));
		cbDst = cbSrc;
		memcpy_s(pbDst, cbDst, pbSrc, cbSrc);
	}
	else
	{
		pbDst = nullptr;
		cbDst = 0;
	}
}


static void Reset(unsigned char*& pbDst, ULONG& cbDst, ULONG cb)
{
	pbDst = reinterpret_cast<unsigned char*>(Allocate(cb));
	cbDst = cb;
	memset(pbDst, 0, cbDst);
}


BCryptAuthenticatedCipherModeInfo::BCryptAuthenticatedCipherModeInfo()
	: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
{
	BCRYPT_INIT_AUTH_MODE_INFO(*this);
}


BCryptAuthenticatedCipherModeInfo::BCryptAuthenticatedCipherModeInfo(const BCryptAuthenticatedCipherModeInfo& other)
	: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
{
	BCRYPT_INIT_AUTH_MODE_INFO(*this);
	COPY_PUCHAR_MEMBER(pbNonce, cbNonce, other);
	COPY_PUCHAR_MEMBER(pbAuthData, cbAuthData, other);
	COPY_PUCHAR_MEMBER(pbTag, cbTag, other);
	COPY_PUCHAR_MEMBER(pbMacContext, cbMacContext, other);
	cbAAD = other.cbAAD;
	cbData = other.cbData;
	dwFlags = other.dwFlags;
}


BCryptAuthenticatedCipherModeInfo::~BCryptAuthenticatedCipherModeInfo()
{
	free(pbNonce);
	free(pbAuthData);
	free(pbTag);
	free(pbMacContext);
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::operator =(const BCryptAuthenticatedCipherModeInfo& other)
{
	free(pbNonce);
	free(pbAuthData);
	free(pbTag);
	free(pbMacContext);
	BCRYPT_INIT_AUTH_MODE_INFO(*this);
	COPY_PUCHAR_MEMBER(pbNonce, cbNonce, other);
	COPY_PUCHAR_MEMBER(pbAuthData, cbAuthData, other);
	COPY_PUCHAR_MEMBER(pbTag, cbTag, other);
	COPY_PUCHAR_MEMBER(pbMacContext, cbMacContext, other);
	cbAAD = other.cbAAD;
	cbData = other.cbData;
	dwFlags = other.dwFlags;
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetNonce(const void* ptr, size_t cb)
{
	free(pbNonce);
	Copy(pbNonce, cbNonce, reinterpret_cast<const unsigned char*>(ptr), static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetAuthDataSize(size_t cb)
{
	free(pbAuthData);
	Reset(pbAuthData, cbAuthData, static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetAuthData(const void* ptr, size_t cb)
{
	free(pbAuthData);
	Copy(pbAuthData, cbAuthData, reinterpret_cast<const unsigned char*>(ptr), static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetTagSize(size_t cb)
{
	free(pbTag);
	Reset(pbTag, cbTag, static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetTag(const void* ptr, size_t cb)
{
	free(pbTag);
	Copy(pbTag, cbTag, reinterpret_cast<const unsigned char*>(ptr), static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetMacContextSize(size_t cb)
{
	free(pbMacContext);
	Reset(pbMacContext, cbMacContext, static_cast<ULONG>(cb));
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetDataSize(size_t cb)
{
	cbData = static_cast<ULONG>(cb);
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::SetFlags(ULONG dw)
{
	dwFlags |= dw;
	return *this;
}


BCryptAuthenticatedCipherModeInfo& BCryptAuthenticatedCipherModeInfo::ResetFlags(ULONG dw)
{
	dwFlags &= ~dw;
	return *this;
}
