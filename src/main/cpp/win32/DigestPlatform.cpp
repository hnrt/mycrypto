// Copyright (C) 2026 Hideaki Narita


#include "DigestPlatform.h"
#include "Digest.h"
#include "DigestMode.h"
#include "ByteString.h"
#include "Debug.h"
#include <Windows.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)
#include <bcrypt.h>
#include <stdexcept>


using namespace hnrt;


static LPCWSTR GetAlgorithm(DigestMode mode)
{
	switch (mode)
	{
	case DigestMode::MD5:
		return BCRYPT_MD5_ALGORITHM;
	case DigestMode::SHA1:
		return BCRYPT_SHA1_ALGORITHM;
	case DigestMode::SHA256:
		return BCRYPT_SHA256_ALGORITHM;
	case DigestMode::SHA384:
		return BCRYPT_SHA384_ALGORITHM;
	case DigestMode::SHA512:
		return BCRYPT_SHA512_ALGORITHM;
	default:
		throw std::runtime_error("Bad digest mode.");
	}
}


DigestPlatform::DigestPlatform(DigestMode dm)
	: Digest(dm)
	, _hA()
	, _h()
	, _length(-1)
{
	DEBUG("#DigestPlatform::ctor\n");
	_hA.Open(GetAlgorithm(_dm));
	_h.Open(_hA);
	_length = static_cast<int>(_hA.HashLength);
}


DigestPlatform::~DigestPlatform()
{
	DEBUG("#DigestPlatform::dtor\n");
}


int DigestPlatform::GetLength() const
{
	DEBUG("#DigestPlatform::GetLength: return=%d\n", _length);
	return _length;
}


void DigestPlatform::Update(const void* ptr, size_t len)
{
	DEBUG("#DigestPlatform::Update(%zu)\n", len);
	_h.Feed(const_cast<void*>(ptr), len);
}


ByteString DigestPlatform::Finalize()
{
	DEBUG("#DigestPlatform::Finalize\n");
	ByteString result(_length);
	_h.Finalize(result, result.Length());
	return result;
}
