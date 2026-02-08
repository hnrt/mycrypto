// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCCM.h"
#include "Encrypter.h"
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


EncrypterCCM::EncrypterCCM(CipherMode cm)
	: Encrypter(cm)
	, _aad()
	, _buf(nullptr)
	, _cap(0)
	, _len(0)
{
	DEBUG("#EncrypterCCM::ctor\n");
}


EncrypterCCM::~EncrypterCCM()
{
	DEBUG("#EncrypterCCM::dtor\n");
	free(_buf);
}


void EncrypterCCM::SetKeyIv(void* key, void* iv)
{
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}

	int defaultTagLength = EVP_CIPHER_CTX_get_tag_length(_ctx);

	DEBUG("#EVP_CIPHER_CTX_get_tag_length=%d\n", defaultTagLength);

	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_CCM_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()));
	}

	if (GetTagLength() != defaultTagLength)
	{
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_CCM_SET_TAG, GetTagLength(), NULL) != 1)
		{
			throw std::runtime_error(String::Format("Failed to set the AEAD tag length: %s", ErrorMessage().Ptr()).Ptr());
		}
	}

	if (EVP_EncryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
}


void EncrypterCCM::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCCM::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}


void EncrypterCCM::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#EncrypterCCM::SetKey(k,i,a)\n");
	SetKeyIv(key, iv);
	_aad = ByteString(aad, len);
}


ByteString EncrypterCCM::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#EncrypterCCM::Update(%zu): Started.\n", inputLength);

	if (_cap < _len + inputLength)
	{
		size_t cap = _len + inputLength + 8192;
		_buf = reinterpret_cast<unsigned char*>(Reallocate(_buf, cap));
		_cap = cap;
	}

	memcpy(_buf + _len, inputBuffer, inputLength);
	_len += inputLength;

	DEBUG("#EncrypterCCM::Update(%zu): Finished. return=0\n", inputLength);

	return ByteString();
}


ByteString EncrypterCCM::Finalize(void* inputBuffer, size_t inputLength)
{
	Update(inputBuffer, inputLength);

	DEBUG("#EncrypterCCM::Finalize: Started.\n");

	int outputLength = -1;

	if (EVP_EncryptUpdate(_ctx, NULL, &outputLength, NULL, static_cast<int>(_len)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to set payload size of %zu bytes: %s", _len, ErrorMessage().Ptr()));
	}
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_EncryptUpdate returned a length less than zero.");
	}
	DEBUG("#EncrypterCCM::Finalize: expected outputLength=%d\n", outputLength);

	if (_aad)
	{
		int length = -1;

		DEBUG("#EncrypterCCM::Finalize: AAD=[%zu]{%s}\n", _aad.Length(), String::Hex(_aad).Ptr());
		if (EVP_EncryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
		{
			throw std::runtime_error("Failed to set AAD in the cipher context.");
		}

		_aad = ByteString();
	}

	ByteString outputBuffer(outputLength);

	if (EVP_EncryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(_buf), static_cast<int>(_len)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to encrypt %zu bytes: %s", _len, ErrorMessage().Ptr()));
	}
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_EncryptUpdate returned a length less than zero.");
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Encryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()));
	}
	else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
	{
		DEBUG("#EncrypterCCM::Finalize: actual outputLength=%d\n", outputLength);
		outputBuffer = ByteString(outputBuffer, outputLength);
	}

	DEBUG("#EncrypterCCM::Finalize: Finished. return=%d\n", outputLength);

	return outputBuffer;
}
