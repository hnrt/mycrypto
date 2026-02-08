// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCCM.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


EncrypterCCM::EncrypterCCM(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCCM::ctor\n");
}


EncrypterCCM::~EncrypterCCM()
{
	DEBUG("#EncrypterCCM::dtor\n");
}


void EncrypterCCM::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCCM::SetKey(k,i)\n");
	SetKeyIvTagLength(key, iv);
}


void EncrypterCCM::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#EncrypterCCM::SetKey(k,i,a)\n");
	SetKeyIvTagLength(key, iv);
	_info.SetAuthData(aad, len);
}


ByteString EncrypterCCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterCCM::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = UpdateAEAD(inputBuffer, inputLength);
	DEBUG("#EncrypterCCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString EncrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterCCM::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
	DEBUG("#EncrypterCCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
