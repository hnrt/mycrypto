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


void Encrypter::SetKeyAndIv(void* key, void* iv)
{
	DEBUG("#Encrypter::SetKeyAndIv\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
	switch (_cm)
	{
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
	case CipherMode::AES_128_CFB:
	case CipherMode::AES_192_CFB:
	case CipherMode::AES_256_CFB:
		memcpy(_iv, iv, _iv.Length());
		break;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	{
#ifdef _DEBUG
		Array<DWORD> tagLengths = _hA.AuthTagLengths;
		String tmp;
		for (int i = 0; i < tagLengths.Length(); i++)
		{
			tmp += String::Format(",%lu", tagLengths[i]);
		}
		DEBUG("#tagLengths=%s\n", tmp.Ptr() + 1);
#endif //_DEBUG
		_info
			.SetNonce(iv, GetIvLength())
			.SetTagSize(GetTagLength());
		memset(_iv, 0, _iv.Length());
		break;
	}
	default:
		break;
	}
}


void Encrypter::SetKey(void* key)
{
	DEBUG("#Encrypter::SetKey\n");
	_hA.Open(GetAlgorithm());
	_hA.SetChainingMode(GetChainingMode());
	_hK.Generate(_hA, key, GetKeyLength());
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu)\n", inputLength);
	if (_info.cbNonce)
	{
		if (!_info.cbMacContext)
		{
			_info.SetMacContextSize(AES_BLOCK_LENGTH);
		}
		_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
	}
	else if (GetIvLength())
	{
		return _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
	}
	else
	{
		return _hK.Encrypt(inputBuffer, inputLength);
	}
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Finalize(%zu)\n", inputLength);
	if (_info.cbNonce)
	{
		_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
		return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
	}
	else
	{
		ByteString last = ByteString(inputBuffer, inputLength).Pkcs7Padding(AES_BLOCK_LENGTH);
		if (GetIvLength())
		{
			return _hK.Encrypt(last, last.Length(), _iv, _iv.Length());
		}
		else
		{
			return _hK.Encrypt(last, last.Length());
		}
	}
}
