// Copyright (C) 2026 Hideaki Narita


#include "Decrypter.h"
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


Decrypter::Decrypter(CipherMode cm)
	: CipherPlatform(cm)
{
	DEBUG("#Decrypter::ctor\n");
}


Decrypter::~Decrypter()
{
	DEBUG("#Decrypter::dtor\n");
}


void Decrypter::SetKey(void* key)
{
	DEBUG("#Decrypter::SetKey(k)\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
}


void Decrypter::SetKey(void* key, void* iv)
{
	DEBUG("#Decrypter::SetKey(k,i)\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	memcpy(_iv, iv, _iv.Length());
}


void Decrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#Decrypter::SetKey(k,i,a)\n");
	throw std::runtime_error("TAG is required for the AEAD decryption operation.");
}


void Decrypter::SetKey(void* key, void* iv, void*tag)
{
	DEBUG("#Decrypter::SetKey(k,i,t)\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	_info
		.SetNonce(iv, GetNonceLength())
		.SetTag(tag, GetTagLength());
	memset(_iv, 0, _iv.Length());
}


void Decrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#Decrypter::SetKey(k,i,t,a)\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	_info
		.SetNonce(iv, GetNonceLength())
		.SetTag(tag, GetTagLength())
		.SetAuthData(aad, len);
	memset(_iv, 0, _iv.Length());
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer;
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength);
		break;
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
		break;
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
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
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
		break;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
	DEBUG("#Decrypter::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


static ByteString RemovePadding(const ByteString& bs)
{
	if (bs.Length() < AES_BLOCK_LENGTH)
	{
		throw std::runtime_error("Decrypted data truncated.");
	}
	size_t paddingLength = bs[bs.Length() - 1];
	if (paddingLength < 1 || AES_BLOCK_LENGTH < paddingLength)
	{
		throw std::runtime_error("Decrypted data corrupted.");
	}
	return ByteString(bs, bs.Length() - paddingLength);
}


ByteString Decrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer;
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		outputBuffer = RemovePadding(_hK.Decrypt(inputBuffer, inputLength));
		break;
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		outputBuffer = RemovePadding(_hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length()));
		break;
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
		break;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
		break;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
	DEBUG("#Decrypter::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
