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


void Decrypter::SetKeyAndIv(void* key, void* iv)
{
	DEBUG("#Decrypter::SetKeyAndIv\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	switch (_cm)
	{
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		memcpy(_iv, iv, _iv.Length());
		break;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
	{
		Array<DWORD> tagLengths = _hA.AuthTagLengths;
		_info
			.SetNonce(iv, GetIvLength())
			.SetMacContextSize(tagLengths[-1]);
		memset(_iv, 0, _iv.Length());
		break;
	}
	default:
		break;
	}
}


void Decrypter::SetKey(void* key)
{
	DEBUG("#Decrypter::SetKey\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Update(%zu)\n", inputLength);
	if (_info.cbNonce)
	{
		_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		return _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
	}
	else if (GetIvLength())
	{
		return _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
	}
	else
	{
		return _hK.Decrypt(inputBuffer, inputLength);
	}
}


ByteString Decrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Finalize(%zu)\n", inputLength);
	if (_info.cbNonce)
	{
		_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		return _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
	}
	else
	{
		ByteString last;
		if (GetIvLength())
		{
			last = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
		}
		else
		{
			last = _hK.Decrypt(inputBuffer, inputLength);
		}
		if (last.Length() < AES_BLOCK_LENGTH)
		{
			throw std::runtime_error("Decrypted data truncated.");
		}
		size_t paddingLength = last[last.Length() - 1];
		if (paddingLength > AES_BLOCK_LENGTH)
		{
			throw std::runtime_error("Decrypted data corrupted.");
		}
		return ByteString(last, last.Length() - paddingLength);
	}
}
