// Copyright (C) 2026 Hideaki Narita


#include "DecrypterECB.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


DecrypterECB::DecrypterECB(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterECB::ctor\n");
}


DecrypterECB::~DecrypterECB()
{
	DEBUG("#DecrypterECB::dtor\n");
}


int DecrypterECB::GetIvLength() const
{
	return 0;
}


void DecrypterECB::SetKey(void* key)
{
	DEBUG("#DecrypterECB::SetKey(k)\n");
	SetKeyOnly(key);
}


ByteString DecrypterECB::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterECB::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = _hK.Decrypt(inputBuffer, inputLength);
	DEBUG("#DecrypterECB::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString DecrypterECB::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterECB::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = RemovePadding(_hK.Decrypt(inputBuffer, inputLength));
	DEBUG("#DecrypterECB::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
