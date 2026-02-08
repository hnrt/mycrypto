// Copyright (C) 2026 Hideaki Narita


#include "EncrypterECB.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


EncrypterECB::EncrypterECB(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterECB::ctor\n");
}


EncrypterECB::~EncrypterECB()
{
	DEBUG("#EncrypterECB::dtor\n");
}


void EncrypterECB::SetKey(void* key)
{
	DEBUG("#EncrypterECB::SetKey(k)\n");
	SetKeyOnly(key);
}


ByteString EncrypterECB::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterECB::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Encrypt(inputBuffer, inputLength);
	DEBUG("#EncrypterECB::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString EncrypterECB::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterECB::Finalize(%zu): Started.\n", inputLength);
	ByteString padded = ByteString(inputBuffer, inputLength).Pkcs7Padding(AES_BLOCK_LENGTH);
	ByteString outputBuffer = _hK.Encrypt(padded, padded.Length());
	DEBUG("#EncrypterECB::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
