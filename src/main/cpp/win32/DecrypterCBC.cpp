// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCBC.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


DecrypterCBC::DecrypterCBC(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCBC::ctor\n");
}


DecrypterCBC::~DecrypterCBC()
{
	DEBUG("#DecrypterCBC::dtor\n");
}


void DecrypterCBC::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCBC::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}


ByteString DecrypterCBC::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterCBC::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = RemovePadding(_hK.Decrypt(inputBuffer, inputLength, _iv, _iv.Length()));
	DEBUG("#DecrypterCBC::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
