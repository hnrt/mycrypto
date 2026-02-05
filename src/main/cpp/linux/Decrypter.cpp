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


void Decrypter::SetKeyAndIv(void* key, void* iv)
{
	switch (_cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
		{
			throw std::runtime_error("Failed to initialize the cipher context.");
		}
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetIvLength(), NULL) != 1)
		{
			throw std::runtime_error(String::Format("Failed to configure the cipher context with the IV size set to %d.", GetIvLength()).Ptr());
		}
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, GetTagLength(), NULL) != 1)
		{
			throw std::runtime_error("Failed to set the AEAD tag.");
		}
		if (EVP_DecryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
		{
			throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
		}
		break;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
		{
			throw std::runtime_error("Failed to initialize the cipher context.");
		}
		if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, GetIvLength(), NULL) != 1)
		{
			throw std::runtime_error(String::Format("Failed to configure the cipher context with the IV size set to %d.", GetIvLength()).Ptr());
		}
		if (EVP_DecryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
		{
			throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
		}
		break;
	default:
		if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
		{
			throw std::runtime_error("Failed to initialize the cipher context.");
		}
		break;
	}
}


void Decrypter::SetKey(void* key)
{
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}


void Decrypter::SetPayloadLength(size_t len)
{
	switch (_cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	{
		int length = -1;
		EVP_DecryptUpdate(_ctx, NULL, &length, NULL, static_cast<int>(len));
		break;
	}
	default:
		break;
	}
}


void Decrypter::SetAdditionalAuthenticatedData(void* ptr, size_t len)
{
	switch (_cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
	{
		int length = -1;
		EVP_DecryptUpdate(_ctx, NULL, &length, NULL, static_cast<int>(len));
		break;
	}
	default:
		break;
	}
	int length = -1;
	if (EVP_DecryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(ptr), len) != 1)
	{
		throw std::runtime_error("Failed to set AAD in the cipher context.");
	}
}


ByteString Decrypter::Update(void* inputBuffer, size_t inputLength)
{
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	size_t required = ((inputLength + blockSize - 1) / blockSize) * blockSize;
	ByteString outputBuffer(required);
	int length = -1;
	if (EVP_DecryptUpdate(_ctx, outputBuffer, &length, reinterpret_cast<unsigned char*>(inputBuffer), static_cast<int>(inputLength)) != 1)
	{
		throw std::runtime_error(String::Format("Failed to decrypt %zu bytes.", inputLength).Ptr());
	}
	else if (outputBuffer.Length() < static_cast<size_t>(length))
	{
		throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(length) - outputBuffer.Length()).Ptr());
	}
	DEBUG("#Decrypter::Update: return=%d\n", length);
	if (static_cast<size_t>(length) < outputBuffer.Length())
	{
		outputBuffer = ByteString(outputBuffer, length);
	}
	return outputBuffer;
}


ByteString Decrypter::Finalize(void* inputBuffer, size_t inputLength)
{
	ByteString outputBuffer1 = Update(inputBuffer, inputLength);
	size_t blockSize = EVP_CIPHER_CTX_block_size(_ctx);
	ByteString outputBuffer2(blockSize);
	int length = -1;
	if (EVP_DecryptFinal_ex(_ctx, outputBuffer2, &length) != 1)
	{
		throw std::runtime_error("Failed to finalize the decryption.");
	}
	else if (outputBuffer2.Length() < static_cast<size_t>(length))
	{
		throw std::runtime_error(String::Format("Decryption buffer overrun %zu bytes.", static_cast<size_t>(length) - outputBuffer2.Length()).Ptr());
	}
	DEBUG("#Decrypter::Finalize: return=%d\n", length);
	return outputBuffer1 + ByteString(outputBuffer2, length);
}
