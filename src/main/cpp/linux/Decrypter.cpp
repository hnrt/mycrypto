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
{
	DEBUG("#Decrypter::ctor\n");
}


Decrypter::~Decrypter()
{
	DEBUG("#Decrypter::dtor\n");
}


void Decrypter::SetKey(void* key)
{
	throw std::runtime_error("Decrypter::SetKey(k): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv)
{
	throw std::runtime_error("Decrypter::SetKey(k,i): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,a): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* tag)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,t): Invalid operation for the current context.");
}


void Decrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	throw std::runtime_error("Decrypter::SetKey(k,i,t,a): Invalid operation for the current context.");
}


void Decrypter::SetKeyIv(void* key, void* iv)
{
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Decrypter::SetKeyIvTag(void* key, void* iv, void* tag)
{
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}

	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()));
	}

	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), reinterpret_cast<unsigned char*>(tag)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to set the AEAD tag: %s", ErrorMessage().Ptr()));
	}

	if (EVP_DecryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Decrypter::Update(%zu): Started.\n", inputLength);

	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
	DEBUG("#Decrypter::Update(%zu): computed outputLength=%zu\n", inputLength, required);
	ByteString outputBuffer(required);
	int outputLength = -1;

	if (EVP_DecryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to decrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()));
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
		DEBUG("#Decrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
		outputBuffer = ByteString(outputBuffer, outputLength);
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
		throw std::runtime_error(String::Format("Failed to finalize the decryption: %s", ErrorMessage().Ptr()));
	}
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_DecryptUpdate returned a length less than zero.");
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()));
	}

	DEBUG("#Decrypter::Finalize: Finished. return=%d\n", outputLength);

	outputBuffer = outputBufferPreceding + ByteString(outputBuffer, outputLength);

	return outputBuffer;
}
