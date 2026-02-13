// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCCM.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "AESCCM.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptKeyHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <stddef.h>
#ifdef CCM_BUFFERING
#include "Heap.h"
#include <stdlib.h>
#endif //CCM_BUFFERING


using namespace hnrt;


EncrypterCCM::EncrypterCCM(CipherMode cm)
	: Encrypter(cm)
	, _nonceLength(AES_CCM_NONCE_LENGTH_DEFAULT)
	, _tagLength(AES_CCM_TAG_LENGTH_DEFAULT)
#ifdef CCM_BUFFERING
	, _buf(nullptr)
	, _cap(0)
	, _len(0)
#endif //CCM_BUFFERING
{
	DEBUG("#EncrypterCCM::ctor\n");
}


EncrypterCCM::~EncrypterCCM()
{
	DEBUG("#EncrypterCCM::dtor\n");
#ifdef CCM_BUFFERING
	free(_buf);
#endif //CCM_BUFFERING
}


int EncrypterCCM::GetNonceLength() const
{
	return _nonceLength;
}


void EncrypterCCM::SetNonceLength(int len)
{
	aes_ccm::SetNonceLength(_nonceLength, len);
}


int EncrypterCCM::GetTagLength() const
{
	return _tagLength;
}


void EncrypterCCM::SetTagLength(int len)
{
	aes_ccm::SetTagLength(_tagLength, len);
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
#ifdef CCM_BUFFERING
	if (_cap < _len + inputLength)
	{
		size_t cap = _len + inputLength;
		cap |= cap >> 1;
		cap |= cap >> 2;
		cap |= cap >> 4;
		cap |= cap >> 8;
		cap |= cap >> 16;
		cap |= cap >> 32;
		cap++;
		DEBUG("#EncrypterCCM::Update(%zu): cap=%zu\n", inputLength, cap);
		_buf = reinterpret_cast<unsigned char*>(Reallocate(_buf, cap));
		_cap = cap;
	}
	memcpy_s(_buf + _len, _cap - _len, inputBuffer, inputLength);
	_len += inputLength;
	ByteString outputBuffer;
#else //CCM_BUFFERING
	ByteString outputBuffer = UpdateAEAD(inputBuffer, inputLength);
#endif //CCM_BUFFERING
	DEBUG("#EncrypterCCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString EncrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterCCM::Finalize(%zu): Started.\n", inputLength);
#ifdef CCM_BUFFERING
	Update(inputBuffer, inputLength);
	ByteString outputBuffer = FinalizeAEAD(_buf, _len);
#else //CCM_BUFFERING
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
#endif //CCM_BUFFERING
	DEBUG("#EncrypterCCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
