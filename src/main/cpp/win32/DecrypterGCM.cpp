// Copyright (C) 2026 Hideaki Narita


#include "DecrypterGCM.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


DecrypterGCM::DecrypterGCM(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterGCM::ctor\n");
}


DecrypterGCM::~DecrypterGCM()
{
	DEBUG("#DecrypterGCM::dtor\n");
}


void DecrypterGCM::SetKey(void* key, void* iv, void* tag)
{
	DEBUG("#DecrypterGCM::SetKey(k,i,t)\n");
	SetKeyIvTag(key, iv, tag);
}


void DecrypterGCM::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#DecrypterGCM::SetKey(k,i,t,a)\n");
	SetKeyIvTag(key, iv, tag);
	_info.SetAuthData(aad, len);
}


ByteString DecrypterGCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterGCM::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer = UpdateAEAD(inputBuffer, inputLength);
	DEBUG("#DecrypterGCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString DecrypterGCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterGCM::Finalize(%zu): Started.\n", inputLength);
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
	DEBUG("#DecrypterGCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
