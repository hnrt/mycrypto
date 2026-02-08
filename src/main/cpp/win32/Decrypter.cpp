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


ByteString Decrypter::RemovePadding(const ByteString& bs)
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
	throw std::runtime_error("Decrypter::SetKey(k): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv)
{
	throw std::runtime_error("Decrypter::SetKey(k,i): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,a): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* tag)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,t): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,t,a): Invalid operation for the current context.");
}


ByteString Decrypter::GetTag() const
{
	throw std::runtime_error("Decrypter::GetTag: Invalid operation for the current context.");
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
	DEBUG("#Decrypter::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString Decrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length());
	DEBUG("#Decrypter::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString Decrypter::UpdateAEAD(void* inputBuffer, size_t inputLength)
{
	if (!_info.cbMacContext)
	{
		SetMacContextSize();
	}
	_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}


ByteString Decrypter::FinalizeAEAD(void* inputBuffer, size_t inputLength)
{
	_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Decrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}
