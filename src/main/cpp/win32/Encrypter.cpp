// Copyright (C) 2026 Hideaki Narita


#include "Encrypter.h"
#include "Cipher.h"
#include "CipherMode.h"
#include "CipherPlatform.h"
#include "ByteString.h"
#include "Array.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <Windows.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


Encrypter::Encrypter(CipherMode cm)
	: CipherPlatform(cm)
{
	DEBUG("#Encrypter::ctor\n");
}


Encrypter::~Encrypter()
{
	DEBUG("#Encrypter::dtor\n");
}


void Encrypter::SetKey(void* key)
{
	DEBUG("#Encrypter::SetKey\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
}


void Encrypter::SetKey(void* key, void* iv)
{
	DEBUG("#Encrypter::SetKey\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	switch (_cm)
	{
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		memcpy(_iv, iv, _iv.Length());
		break;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		_info
			.SetNonce(iv, GetIvLength())
			.SetTagSize(GetTagLength());
		memset(_iv, 0, _iv.Length());
		break;
	default:
		break;
	}
}


void Encrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#Encrypter::SetKey\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	_info
		.SetNonce(iv, GetNonceLength())
		.SetTagSize(GetTagLength())
		.SetAuthData(aad, len);
	memset(_iv, 0, _iv.Length());
}


void Encrypter::SetKey(void* key, void* iv, void* tag)
{
	throw std::runtime_error("Unable to set TAG for the encryption operation.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	throw std::runtime_error("Unable to set TAG for the encryption operation.");
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer;
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength);
		break;
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
		break;
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
		break;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		if (!_info.cbMacContext)
		{
			SetMacContextSize();
		}
		_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
		break;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
	DEBUG("#Encrypter::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer;
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
	{
		ByteString padded = ByteString(inputBuffer, inputLength).Pkcs7Padding(AES_BLOCK_LENGTH);
		outputBuffer = _hK.Encrypt(padded, padded.Length());
		break;
	}
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
	{
		ByteString padded = ByteString(inputBuffer, inputLength).Pkcs7Padding(AES_BLOCK_LENGTH);
		outputBuffer = _hK.Encrypt(padded, padded.Length(), _iv, _iv.Length());
		break;
	}
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
		break;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
		break;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
	DEBUG("#Encrypter::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
