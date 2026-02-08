// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCCM.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Heap.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <string.h>
#include <stdexcept>


using namespace hnrt;


DecrypterCCM::DecrypterCCM(CipherMode cm)
	: Decrypter(cm)
	, _aad()
	, _buf(nullptr)
	, _cap(0)
	, _len(0)
{
	DEBUG("#DecrypterCCM::ctor\n");
}


DecrypterCCM::~DecrypterCCM()
{
	DEBUG("#DecrypterCCM::dtor\n");
	free(_buf);
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
	_aad = ByteString(aad, len);
}


ByteString DecrypterCCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#DecrypterCCM::Update(%zu): Started.\n", inputLength);

	if (_cap < _len + inputLength)
	{
		size_t cap = _len + inputLength + 8192;
		_buf = reinterpret_cast<unsigned char*>(Reallocate(_buf, cap));
		_cap = cap;
	}

	memcpy(_buf + _len, inputBuffer, inputLength);
	_len += inputLength;

	DEBUG("#DecrypterCCM::Update(%zu): Finished. return=0\n", inputLength);

	return ByteString();
}


ByteString DecrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	Update(inputBuffer, inputLength);

	DEBUG("#DecrypterCCM::Finalize: Started.\n");

	int outputLength = -1;

	if (EVP_DecryptUpdate(_ctx, NULL, &outputLength, NULL, static_cast<int>(_len)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to set payload size of %zu bytes: %s", inputLength, ErrorMessage().Ptr()));
	}
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_DecryptUpdate returned a length less than zero.");
	}
	DEBUG("#DecrypterCCM::Finalize: expected outputLength=%d\n", outputLength);

	if (_aad)
	{
		int length = -1;

		DEBUG("#DecrypterCCM::Finalize: AAD=[%zu]{%s}\n", _aad.Length(), String::Hex(_aad).Ptr());
		if (EVP_DecryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
		{
			throw std::runtime_error("Failed to set AAD in the cipher context.");
		}

		_aad = ByteString();
	}

	ByteString outputBuffer(outputLength);

	if (EVP_DecryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(_buf), static_cast<int>(_len)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to decrypt %zu bytes: %s", _len, ErrorMessage().Ptr()));
	}
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_DecryptUpdate returned a length less than zero.");
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()));
	}
	else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
	{
		DEBUG("#DecrypterCCM::Finalize: actual outputLength=%d\n", outputLength);
		outputBuffer = ByteString(outputBuffer, outputLength);
	}

	DEBUG("#DecrypterCCM::Finalize: Finished. return=%d\n", outputLength);

	return outputBuffer;
}
