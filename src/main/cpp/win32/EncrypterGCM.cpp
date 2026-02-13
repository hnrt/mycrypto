// Copyright (C) 2026 Hideaki Narita


#include "EncrypterGCM.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "AESGCM.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>


using namespace hnrt;


EncrypterGCM::EncrypterGCM(CipherMode cm)
	: Encrypter(cm)
	, _nonceLength(AES_GCM_NONCE_LENGTH_DEFAULT)
	, _tagLength(AES_GCM_TAG_LENGTH_DEFAULT)
{
	DEBUG("#EncrypterGCM::ctor\n");
}


EncrypterGCM::~EncrypterGCM()
{
	DEBUG("#EncrypterGCM::dtor\n");
}


int EncrypterGCM::GetNonceLength() const
{
	return _nonceLength;
}


void EncrypterGCM::SetNonceLength(int len)
{
	aes_gcm::SetNonceLength(_nonceLength, len);
}


int EncrypterGCM::GetTagLength() const
{
	return _tagLength;
}


void EncrypterGCM::SetTagLength(int len)
{
	aes_gcm::SetTagLength(_tagLength, len);
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
