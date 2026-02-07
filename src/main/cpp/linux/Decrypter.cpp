// Copyright (C) 2026 Hideaki Narita


#include "Decrypter.h"
#include "CipherPlatform.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


Decrypter::Decrypter(CipherMode cm)
	: CipherPlatform(cm)
	, _aad()
{
	DEBUG("#Decrypter::ctor\n");
}


Decrypter::~Decrypter()
{
	DEBUG("#Decrypter::dtor\n");
}


void Decrypter::SetKey(void* key)
{
	DEBUG("#Decrypter::SetKey(k)\n");
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Decrypter::SetKey(void* key, void* iv)
{
	DEBUG("#Decrypter::SetKey(k,i)\n");
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Decrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#Decrypter::SetKey(k,i,a)\n");
	throw std::runtime_error("TAG is required for the AEAD decryption operation.");
}


void Decrypter::SetKey(void* key, void* iv, void* tag)
{
	DEBUG("#Decrypter::SetKey(k,i,t)\n");
	DEBUG("#EVP_DecryptInit_ex\n");
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
	DEBUG("#EVP_CTRL_AEAD_SET_IVLEN(%d)\n", GetNonceLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()).Ptr());
	}
	DEBUG("#EVP_CTRL_AEAD_SET_TAG(%d)\n", GetTagLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), reinterpret_cast<unsigned char*>(tag)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to set the AEAD tag: %s", ErrorMessage().Ptr()).Ptr());
	}
	DEBUG("#EVP_DecryptInit_ex(k,i)\n");
	if (EVP_DecryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
}


void Decrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#Decrypter::SetKey(k,i,t,a)\n");
	DEBUG("#EVP_DecryptInit_ex\n");
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
	DEBUG("#EVP_CTRL_AEAD_SET_IVLEN(%d)\n", GetNonceLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()).Ptr());
	}
	DEBUG("#EVP_CTRL_AEAD_SET_TAG(%d)\n", GetTagLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), reinterpret_cast<unsigned char*>(tag)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to set the AEAD tag: %s", ErrorMessage().Ptr()).Ptr());
	}
	DEBUG("#EVP_DecryptInit_ex(k,i)\n");
	if (EVP_DecryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
	_aad = ByteString(aad, len);
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Update(%zu): Started.\n", inputLength);
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
			DEBUG("#Decrypter::Update(%zu): AAD=%zu\n", inputLength, _aad.Length());
			if (EVP_DecryptUpdate(_ctx, NULL, &length, NULL, static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error(String::Format("Failed to set AAD size of %zu bytes: %s", _aad.Length(), ErrorMessage().Ptr()).Ptr());
			}
			DEBUG("#Decrypter::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad, _aad.Length()).Ptr());
			if (EVP_DecryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error("Failed to set AAD in the cipher context.");
			}
			_aad = ByteString();
		}
		if (EVP_DecryptUpdate(_ctx, NULL, &outputLength, NULL, static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to set payload size of %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		DEBUG("#Decrypter::Update(%zu): expected outputLength=%d\n", inputLength, outputLength);
		outputBuffer = ByteString(outputLength);
		if (EVP_DecryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to decrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
		{
			throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
		}
		else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
		{
			DEBUG("#Decrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
			outputBuffer = ByteString(outputBuffer, outputLength);
		}
		break;
	default:
	{
		if (_aad)
		{
			int length = -1;
			DEBUG("#Decrypter::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad, _aad.Length()).Ptr());
			if (EVP_DecryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
			{
				throw std::runtime_error("Failed to set AAD in the cipher context.");
			}
			_aad = ByteString();
		}
		size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
		size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
		DEBUG("#Decrypter::Update(%zu): computed outputLength=%zu\n", inputLength, required);
		outputBuffer = ByteString(required);
		if (EVP_DecryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
		{
			throw std::runtime_error(String::Format("Failed to decrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()).Ptr());
		}
		else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
		{
			throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
		}
		else if (static_cast<size_t>(outputLength) < outputBuffer.Length())
		{
			DEBUG("#Decrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
			outputBuffer = ByteString(outputBuffer, outputLength);
		}
		break;
	}
	}
	DEBUG("#Decrypter::Update(%zu): Finished. return=%d\n", inputLength, outputLength);
	return outputBuffer;
}


ByteString Decrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	ByteString outputBufferPreceding = Update(inputBuffer, inputLength);
	DEBUG("#Decrypter::Finalize: Started.\n");
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	ByteString outputBuffer(blockSize);
	int outputLength = -1;
	if (EVP_DecryptFinal_ex(_ctx, outputBuffer, &outputLength) != 1)
	{
		throw std::runtime_error(String::Format("Failed to finalize the decryption: %s", ErrorMessage().Ptr()).Ptr());
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
	}
	DEBUG("#Decrypter::Finalize: Finished. return=%d\n", outputLength);
	outputBuffer = outputBufferPreceding + ByteString(outputBuffer, outputLength);
	return outputBuffer;
}
