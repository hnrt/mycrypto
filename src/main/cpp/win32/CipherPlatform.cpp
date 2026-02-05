// Copyright (C) 2026 Hideaki Narita


#include "CipherPlatform.h"
#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <Windows.h>
#include <stdexcept>


using namespace hnrt;


CipherPlatform::CipherPlatform(CipherMode cm)
	: Cipher(cm)
	, _hA()
	, _hK()
	, _info()
	, _iv(AES_BLOCK_LENGTH)
{
	DEBUG("#CipherPlatform::ctor\n");
}


CipherPlatform::~CipherPlatform()
{
	DEBUG("#CipherPlatform::dtor\n");
}


LPCWSTR CipherPlatform::GetAlgorithm()
{
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
	case CipherMode::AES_128_OFB:
	case CipherMode::AES_192_OFB:
	case CipherMode::AES_256_OFB:
	case CipherMode::AES_128_CTR:
	case CipherMode::AES_192_CTR:
	case CipherMode::AES_256_CTR:
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return BCRYPT_AES_ALGORITHM;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


LPCWSTR CipherPlatform::GetChainingMode()
{
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		return BCRYPT_CHAIN_MODE_ECB;
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		return BCRYPT_CHAIN_MODE_CBC;
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
		return BCRYPT_CHAIN_MODE_CFB;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		return BCRYPT_CHAIN_MODE_CCM;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return BCRYPT_CHAIN_MODE_GCM;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


void CipherPlatform::SetAdditionalAuthenticatedData(void* ptr, size_t len)
{
	_info.SetAuthData(ptr, len);
}


ByteString CipherPlatform::GetTag()
{
	return ByteString(_info.pbTag, _info.cbTag);
}


void CipherPlatform::SetTag(void* ptr, size_t len)
{
	_info.SetTag(ptr, len);
}
