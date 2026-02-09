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
#ifdef CCM_BUFFERING
#include "Heap.h"
#include <stdlib.h>
#endif //CCM_BUFFERING


using namespace hnrt;


DecrypterCCM::DecrypterCCM(CipherMode cm)
	: Decrypter(cm)
#ifdef CCM_BUFFERING
	, _buf(nullptr)
	, _cap(0)
	, _len(0)
#endif //CCM_BUFFERING
{
	DEBUG("#DecrypterCCM::ctor\n");
}


DecrypterCCM::~DecrypterCCM()
{
	DEBUG("#DecrypterCCM::dtor\n");
#ifdef CCM_BUFFERING
	free(_buf);
#endif //CCM_BUFFERING
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
	DEBUG("#DecrypterCCM::Update(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}


ByteString DecrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterCCM::Finalize(%zu): Started.\n", inputLength);
#ifdef CCM_BUFFERING
	Update(inputBuffer, inputLength);
	ByteString outputBuffer = FinalizeAEAD(_buf, _len);
#else //CCM_BUFFERING
	ByteString outputBuffer = FinalizeAEAD(inputBuffer, inputLength);
#endif //CCM_BUFFERING
	DEBUG("#DecrypterCCM::Finalize(%zu): Finished. return=%zu\n", inputLength, outputBuffer.Length());
	return outputBuffer;
}
