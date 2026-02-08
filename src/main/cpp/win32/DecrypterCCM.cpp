// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCCM.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


DecrypterCCM::DecrypterCCM(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCCM::ctor\n");
}


DecrypterCCM::~DecrypterCCM()
{
	DEBUG("#DecrypterCCM::dtor\n");
}


void DecrypterCCM::SetKey(void* key, void* iv, void* tag)
{
	DEBUG("#DecrypterCCM::SetKey(k,i,t)\n");
	SetKeyIvTag(key, iv, tag);
}


void DecrypterCCM::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#DecrypterCCM::SetKey(k,i,t,a)\n");
	SetKeyIvTag(key, iv, tag);
	_info.SetAuthData(aad, len);
}


ByteString DecrypterCCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterCCM::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = UpdateAEAD(inputBuffer, inputLength);
	DEBUG("#DecrypterCCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString DecrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterCCM::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
	DEBUG("#DecrypterCCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
