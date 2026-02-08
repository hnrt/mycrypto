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
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return BCRYPT_AES_ALGORITHM;
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
	case CipherMode::AES_128_OFB:
	case CipherMode::AES_192_OFB:
	case CipherMode::AES_256_OFB:
	case CipherMode::AES_128_CTR:
	case CipherMode::AES_192_CTR:
	case CipherMode::AES_256_CTR:
		throw std::runtime_error("Unsupported cipher mode.");
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
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		return BCRYPT_CHAIN_MODE_CFB;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		return BCRYPT_CHAIN_MODE_CCM;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return BCRYPT_CHAIN_MODE_GCM;
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
	case CipherMode::AES_128_OFB:
	case CipherMode::AES_192_OFB:
	case CipherMode::AES_256_OFB:
	case CipherMode::AES_128_CTR:
	case CipherMode::AES_192_CTR:
	case CipherMode::AES_256_CTR:
		throw std::runtime_error("Unsupported cipher mode.");
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


void CipherPlatform::SetKeyOnly(void* key)
{
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
}


void CipherPlatform::SetKeyIv(void* key, void* iv)
{
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	memcpy(_iv, iv, _iv.Length());
}


void CipherPlatform::SetKeyIvTagLength(void* key, void* iv)
{
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	_info
		.SetNonce(iv, GetNonceLength())
		.SetTagSize(GetTagLength());
	memset(_iv, 0, _iv.Length());
}


void CipherPlatform::SetKeyIvTag(void* key, void* iv, void* tag)
{
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	_info
		.SetNonce(iv, GetNonceLength())
		.SetTag(tag, GetTagLength());
	memset(_iv, 0, _iv.Length());
}


void CipherPlatform::SetMacContextSize()
{
	Array<DWORD> tagLengths = _hA.AuthTagLengths;
	DWORD cbMacContextSize = AES_BLOCK_LENGTH;
	String tmp;
	for (int i = 0; i < tagLengths.Length(); i++)
	{
		if (cbMacContextSize < tagLengths[i])
		{
			cbMacContextSize = tagLengths[i];
		}
		tmp += String::Format(",%lu", tagLengths[i]);
	}
	DEBUG("#tagLengths=%s cbMacContextSize=%lu\n", tmp.Ptr() + 1, cbMacContextSize);
	_info.SetMacContextSize(cbMacContextSize);
}
