// Copyright (C) 2026 Hideaki Narita


#include "DigestPlatform.h"
#include "Digest.h"
#include "DigestMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


static const EVP_MD* GetAlgorithm(DigestMode mode)
{
	switch (mode)
	{
	case DigestMode::MD5:
		return EVP_md5();
	case DigestMode::SHA1:
		return EVP_sha1();
	case DigestMode::SHA256:
		return EVP_sha256();
	case DigestMode::SHA384:
		return EVP_sha384();
	case DigestMode::SHA512:
		return EVP_sha512();
	default:
		throw std::runtime_error("Bad digest mode.");
	}
}


DigestPlatform::DigestPlatform(DigestMode dm)
	: Digest(dm)
	, _ctx(EVP_MD_CTX_new())
{
	DEBUG("#DigestPlatform@%s::ctor\n", DigestModeText(_dm));
	if (EVP_DigestInit_ex(_ctx, GetAlgorithm(_dm), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the digest context.");
	}
}


DigestPlatform::~DigestPlatform()
{
	DEBUG("#DigestPlatform@%s::dtor\n", DigestModeText(_dm));
	if (_ctx)
	{
		EVP_MD_CTX_free(_ctx);
	}
}


int DigestPlatform::GetLength() const
{
	int length = EVP_MD_size(EVP_MD_CTX_get0_md(_ctx));
	DEBUG("#DigestPlatform@%s::GetLength: %d\n", DigestModeText(_dm), length);
	return length;
}


void DigestPlatform::Update(const void* ptr, size_t len)
{
	DEBUG("#DigestPlatform@%s::Update(%lu)\n", DigestModeText(_dm), len);
	if (EVP_DigestUpdate(_ctx, ptr, len) != 1)
	{
		throw std::runtime_error("Failed to update the digest context.");
	}
}


ByteString DigestPlatform::Finalize()
{
	DEBUG("#DigestPlatform@%s::Finalize: Started.\n", DigestModeText(_dm));
	ByteString result(EVP_MD_size(EVP_MD_CTX_get0_md(_ctx)));
	unsigned int length = 0;
	if (EVP_DigestFinal_ex(_ctx, result, &length) != 1)
	{
		throw std::runtime_error("Failed to finalize the digest context.");
	}
	else if (static_cast<size_t>(length) != result.Length())
	{
		throw std::runtime_error("Failed to finalize the digest context; lengths mismatch.");
	}
	DEBUG("#DigestPlatform@%s::Finalize: Finished. [%zu]{%s}\n", DigestModeText(_dm), result.Length(), String::Hex(result).Ptr());
	return result;
}
