// Copyright (C) 2026 Hideaki Narita


#include "EncrypterGCM.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


EncrypterGCM::EncrypterGCM(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterGCM::ctor\n");
}


EncrypterGCM::~EncrypterGCM()
{
	DEBUG("#EncrypterGCM::dtor\n");
}


void EncrypterGCM::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterGCM::SetKey(k,i)\n");
	SetKeyIvTagLength(key, iv);
}


void EncrypterGCM::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#EncrypterGCM::SetKey(k,i,a)\n");
	SetKeyIvTagLength(key, iv);
	_info.SetAuthData(aad, len);
}


ByteString EncrypterGCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterGCM::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = UpdateAEAD(inputBuffer, inputLength);
	DEBUG("#EncrypterGCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString EncrypterGCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterGCM::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
	DEBUG("#EncrypterGCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
