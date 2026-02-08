// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCBC.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


EncrypterCBC::EncrypterCBC(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCBC::ctor\n");
}


EncrypterCBC::~EncrypterCBC()
{
	DEBUG("#EncrypterCBC::dtor\n");
}


void EncrypterCBC::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCBC::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}


ByteString EncrypterCBC::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterCBC::Finalize(%zu): Started.\n", inputLength);
	ByteString padded = ByteString(inputBuffer, inputLength).Pkcs7Padding(AES_BLOCK_LENGTH);
	ByteString outputBuffer = _hK.Encrypt(padded, padded.Length(), _iv, _iv.Length());
	DEBUG("#EncrypterCBC::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
