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
{
	DEBUG("#Encrypter::ctor\n");
}


Encrypter::~Encrypter()
{
	DEBUG("#Encrypter::dtor\n");
}


void Encrypter::SetKey(void* key)
{
	throw std::runtime_error("Encrypter::SetKey(k): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv)
{
	throw std::runtime_error("Encrypter::SetKey(k,i): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* aad, size_t len)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,a): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,t): Invalid operation for the current context.");
}


void Encrypter::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	throw std::runtime_error("Encrypter::SetKey(k,i,t,a): Invalid operation for the current context.");
}


void Encrypter::SetKeyIv(void* key, void* iv)
{
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	DEBUG("#Encrypter::Update(%zu): Started.\n", inputLength);

	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
	DEBUG("#Encrypter::Update(%zu): computed outputLength=%zu\n", inputLength, required);
	ByteString outputBuffer(required);
	int outputLength = -1;

	if (EVP_EncryptUpdate(_ctx, outputBuffer, &outputLength, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to encrypt %zu bytes: %s", inputLength, ErrorMessage().Ptr()));
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
		DEBUG("#Encrypter::Update(%zu): actual outputLength=%d\n", inputLength, outputLength);
		outputBuffer = ByteString(outputBuffer, outputLength);
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
	else if (outputLength < 0)
	{
		throw std::runtime_error("EVP_EncryptUpdate returned a length less than zero.");
	}
	else if (outputBuffer.Length() < static_cast<size_t>(outputLength))
	{
		throw std::runtime_error(String::Format("Encryption buffer overrun %zu bytes.", static_cast<size_t>(outputLength) - outputBuffer.Length()).Ptr());
	}

	DEBUG("#Encrypter::Finalize: Finished. return=%d\n", outputLength);

	outputBuffer = outputBufferPreceding + ByteString(outputBuffer, outputLength);

	return outputBuffer;
}
