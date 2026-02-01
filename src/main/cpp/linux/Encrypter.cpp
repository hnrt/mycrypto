// Copyright (C) 2026 Hideaki Narita


#include "Encrypter.h"
#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


static const EVP_CIPHER* GetAlgorithm(CipherMode cm)
{
	switch (cm)
	{
	case CipherMode::AES_256_GCM:
		return EVP_aes_256_gcm();
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


Encrypter::Encrypter(CipherMode cm)
	: Cipher(cm)
	, _ctx(EVP_CIPHER_CTX_new())
{
	DEBUG("#Encrypter::ctor\n");
	if (!_ctx)
	{
		throw std::bad_alloc();
	}
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(_cm), NULL, NULL, NULL) != 1)
	{
		EVP_CIPHER_CTX_free(_ctx);
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LENGTH, NULL) != 1)
	{
		EVP_CIPHER_CTX_free(_ctx);
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the IV size set to %d.", GCM_IV_LENGTH).Ptr());
	}
}


Encrypter::~Encrypter()
{
	DEBUG("#Encrypter::dtor\n");
	if (_ctx)
	{
		EVP_CIPHER_CTX_free(_ctx);
	}
}


void Encrypter::SetKeyAndIv(void* key, void* iv)
{
	if (EVP_EncryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
}


void Encrypter::SetAdditionalAuthenticatedData(void* ptr, size_t len)
{
	int length = -1;
	if (EVP_EncryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(ptr), len) != 1)
	{
		throw std::runtime_error("Failed to set AAD in the cipher context.");
	}
}


ByteString Encrypter::Update(void* inputBuffer, size_t inputLength)
{
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
	ByteString outputBuffer(required);
	int length = -1;
	if (EVP_EncryptUpdate(_ctx, outputBuffer, &length, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to encrypt %lu bytes.", inputLength).Ptr());
	}
	else if (outputBuffer.Length() < static_cast<size_t>(length))
	{
		throw std::runtime_error(String::Format("Encryption buffer overrun %lu bytes.", length - static_cast<int>(outputBuffer.Length())).Ptr());
	}
	DEBUG("#Encrypter::Update: return=%d\n", length);
	if (static_cast<size_t>(length) < outputBuffer.Length())
	{
		outputBuffer = ByteString(outputBuffer, length);
	}
	return outputBuffer;
}


ByteString Encrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	ByteString outputBuffer1 = Update(inputBuffer, inputLength);
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	ByteString outputBuffer2(blockSize);
	int length = -1;
	if (EVP_EncryptFinal_ex(_ctx, outputBuffer2, &length) != 1)
	{
		throw std::runtime_error("Failed to finalize the encryption.");
	}
	else if (outputBuffer2.Length() < static_cast<size_t>(length))
	{
		throw std::runtime_error(String::Format("Encryption buffer overrun %lu bytes.", length - static_cast<int>(outputBuffer2.Length())).Ptr());
	}
	DEBUG("#Encrypter::Finalize: return=%d\n", length);
	return outputBuffer1 + outputBuffer2;
}


ByteString Encrypter::GetTag()
{
	ByteString tag(GCM_TAG_LENGTH);
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, tag.Length(), tag) != 1)
	{
		throw std::runtime_error("Failed to get the GCM tag.");
	}
	DEBUG("#Encrypter::GetTag: [%lu]=%s\n", tag.Length(), String::Hex(tag, tag.Length()).Ptr());
	return tag;
}


void Encrypter::SetTag(void* ptr, size_t len)
{
	DEBUG("#Encrypter::SetTag([%lu]=%s)\n", len, String::Hex(ptr, len).Ptr());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, len, reinterpret_cast<unsigned char*>(ptr)) != 1)
	{
		throw std::runtime_error("Failed to set the GCM tag.");
	}
}
