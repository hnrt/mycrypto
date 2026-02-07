// Copyright (C) 2026 Hideaki Narita


#include "Encrypter.h"
#include "CipherPlatform.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


Encrypter::Encrypter(CipherMode cm)
	: CipherPlatform(cm)
	, _aad()
{
	DEBUG("#Encrypter::ctor\n");
}


Encrypter::~Encrypter()
{
	DEBUG("#Encrypter::dtor\n");
}


void Encrypter::SetKey(void* key)
{
	DEBUG("#Encrypter::SetKey(k)\n");
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Encrypter::SetKey(void* key, void* iv)
{
	DEBUG("#Encrypter::SetKey(k,i)\n");
	if (GetNonceLength())
	{
		DEBUG("#EVP_EncryptInit_ex\n");
		if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
		{
			throw std::runtime_error("Failed to initialize the cipher context.");
		}
		DEBUG("#EVP_CTRL_AEAD_SET_IVLEN(%d)\n", GetNonceLength());
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetNonceLength(), NULL) != 1)
		{
			throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()).Ptr());
		}
		if (_cm == CipherMode::AES_128_CCM || _cm == CipherMode::AES_192_CCM || _cm == CipherMode::AES_256_CCM)
		{
			DEBUG("#EVP_CTRL_AEAD_SET_TAG(%d)\n", GetTagLength());
			if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), NULL) != 1)
			{
				throw std::runtime_error(String::Format("Failed to set the AEAD tag length: %s", ErrorMessage().Ptr()).Ptr());
			}
		}
		else
		{
			DEBUG("#default tag length: %d\n", EVP_CIPHER_CTX_get_tag_length(_ctx));
		}
		DEBUG("#EVP_EncryptInit_ex(k,i)\n");
		if (EVP_EncryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
		{
			throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
		}
	}
	else if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Encrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#Encrypter::SetKey(k,i,a)\n");
	DEBUG("#EVP_EncryptInit_ex\n");
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
	DEBUG("#EVP_CTRL_AEAD_SET_IVLEN(%d)\n", GetNonceLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()).Ptr());
	}
	if (_cm == CipherMode::AES_128_CCM || _cm == CipherMode::AES_192_CCM || _cm == CipherMode::AES_256_CCM)
	{
		DEBUG("#EVP_CTRL_AEAD_SET_TAG(%d)\n", GetTagLength());
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), NULL) != 1)
		{
			throw std::runtime_error(String::Format("Failed to set the AEAD tag length: %s", ErrorMessage().Ptr()).Ptr());
		}
	}
	else
	{
		DEBUG("#default tag length: %d\n", EVP_CIPHER_CTX_get_tag_length(_ctx));
	}
	DEBUG("#EVP_EncryptInit_ex(k,i)\n");
	if (EVP_EncryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
	_aad = ByteString(aad, len);
}


void Encrypter::SetKey(void* key, void* iv, void* tag)
{
	DEBUG("#Encrypter::SetKey(k,i,t)\n");
	throw std::runtime_error("Unable to set TAG for the encryption operation.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#Encrypter::SetKey(k,i,t,a)\n");
	throw std::runtime_error("Unable to set TAG for the encryption operation.");
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu): Started.\n", inputLength);
	ByteString outputBuffer;
	int outputLength = -1;
	switch (_cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		if (_aad)
		{
			int length = -1;
			DEBUG("#Encrypter::Update(%zu): AAD=[%zu]\n", inputLength, _aad.Length());
			if (EVP_EncryptUpdate(_ctx, NULL, &length, NULL, static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error(String::Format("Failed to set AAD size of %zu bytes: %s", _aad.Length(), ErrorMessage().Ptr()).Ptr());
			}
			DEBUG("#Encrypter::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad, _aad.Length()).Ptr());
			if (EVP_EncryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error("Failed to set AAD in the cipher context.");
			}
			_aad = ByteString();
		}
		if (EVP_EncryptUpdate(_ctx, NULL, &outputLength, NULL, static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to set payload size of %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		DEBUG("#Encrypter::Update(%zu): expected outputLength=%d\n", inputLength, outputLength);
		outputBuffer = ByteString(outputLength);
		if (EVP_EncryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to encrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
		{
			throw std::runtime_error(String::Format("Encryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
		}
		else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
		{
			DEBUG("#Encrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
			outputBuffer = ByteString(outputBuffer, outputLength);
		}
		break;
	default:
	{
		if (_aad)
		{
			int length = -1;
			DEBUG("#Encrypter::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad, _aad.Length()).Ptr());
			if (EVP_EncryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error("Failed to set AAD in the cipher context.");
			}
			_aad = ByteString();
		}
		size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
		size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
		DEBUG("#Encrypter::Update(%zu): computed outputLength=%zu\n", inputLength, required);
		outputBuffer = ByteString(required);
		if (EVP_EncryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to encrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
		{
			throw std::runtime_error(String::Format("Encryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
		}
		else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
		{
			DEBUG("#Encrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
			outputBuffer = ByteString(outputBuffer, outputLength);
		}
		break;
	}
	}
	DEBUG("#Encrypter::Update(%zu): Finished. return=%d\n", inputLength, outputLength);
	return outputBuffer;
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	ByteString outputBufferPreceding = Update(inputBuffer, inputLength);
	DEBUG("#Encrypter::Finalize: Started.\n");
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	ByteString outputBuffer(blockSize);
	int outputLength = -1;
	if (EVP_EncryptFinal_ex(_ctx, outputBuffer, &outputLength) != 1)
	{
		throw std::runtime_error(String::Format("Failed to finalize the encryption: %s", ErrorMessage().Ptr()).Ptr());
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Encryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
	}
	DEBUG("#Encrypter::Finalize: Finished. return=%d\n", outputLength);
	outputBuffer = outputBufferPreceding + ByteString(outputBuffer, outputLength);
	return outputBuffer;
}
