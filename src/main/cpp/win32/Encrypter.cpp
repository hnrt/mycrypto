// Copyright (C) 2026 Hideaki Narita


#include "Encrypter.h"
#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <Windows.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


static LPCWSTR GetAlgorithm(CipherMode cm)
{
	switch (cm)
	{
	case CipherMode::AES_256_GCM:
		return BCRYPT_AES_ALGORITHM;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


static LPCWSTR GetChainingMode(CipherMode cm)
{
	switch (cm)
	{
	case CipherMode::AES_256_GCM:
		return BCRYPT_CHAIN_MODE_GCM;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


Encrypter::Encrypter(CipherMode cm)
	: Cipher(cm)
	, _hA()
	, _hK()
	, _iv(AES_IV_LENGTH)
	, _info()
{
	DEBUG("#Encrypter::ctor\n");
}


Encrypter::~Encrypter()
{
	DEBUG("#Encrypter::dtor\n");
}


void Encrypter::SetKeyAndIv(void* key, void* iv)
{
	_hA.Open(GetAlgorithm(_cm));
	_hA.SetChainingMode(GetChainingMode(_cm));
	Array<DWORD> tagLengths = _hA.AuthTagLengths;
	_hK.Generate(_hA, key, GetKeyLength());
	switch (_cm)
	{
	case CipherMode::AES_256_GCM:
		_info
			.SetNonce(iv, GetIvLength())
			.SetTagSize(GetTagLength())
			.SetMacContextSize(tagLengths[-1])
			.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		memset(_iv, 0, _iv.Length());
		break;
	default:
		break;
	}
}


void Encrypter::SetAdditionalAuthenticatedData(void* ptr, size_t len)
{
	_info.SetAuthData(ptr, len);
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu)\n", inputLength);
	_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Finalize(%zu)\n", inputLength);
	_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}


ByteString Encrypter::GetTag()
{
	return ByteString(_info.pbTag, _info.cbTag);
}


void Encrypter::SetTag(void* ptr, size_t len)
{
	_info.SetTag(ptr, len);
}
