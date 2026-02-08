// Copyright (C) 2026 Hideaki Narita


#include "Encrypter.h"
#include "CipherMode.h"
#include "CipherPlatform.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
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
	throw std::runtime_error("Encrypter::SetKey(k): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv)
{
	throw std::runtime_error("Encrypter::SetKey(k,i): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,a): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,t): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,t,a): Invalid operation for the current context.");
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
	DEBUG("#Encrypter::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Encrypt(inputBuffer, inputLength, _iv, _iv.Length());
	DEBUG("#Encrypter::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString Encrypter::GetTag() const
{
	return ByteString(_info.pbTag, _info.cbTag);
}


ByteString Encrypter::UpdateAEAD(void* inputBuffer, size_t inputLength)
{
	if (!_info.cbMacContext)
	{
		SetMacContextSize();
	}
	_info.SetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}


ByteString Encrypter::FinalizeAEAD(void* inputBuffer, size_t inputLength)
{
	_info.ResetFlags(BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG);
	return _hK.Encrypt(inputBuffer, inputLength, _info, _iv, _iv.Length());
}
