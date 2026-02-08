// Copyright (C) 2026 Hideaki Narita


#include "EncrypterGCM.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


EncrypterGCM::EncrypterGCM(CipherMode cm)
	: Encrypter(cm)
	, _aad()
{
	DEBUG("#EncrypterGCM::ctor\n");
}


EncrypterGCM::~EncrypterGCM()
{
	DEBUG("#EncrypterGCM::dtor\n");
}


void EncrypterGCM::SetKeyIv(void* key, void* iv)
{
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, NULL, NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}

	int defaultTagLength = EVP_CIPHER_CTX_get_tag_length(_ctx);

	DEBUG("#EVP_CIPHER_CTX_get_tag_length=%d\n", defaultTagLength);

	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, GetNonceLength(), NULL) != 1)
	{
		throw std::runtime_error(String::Format("Failed to configure the cipher context with the NONCE length set to %d.", GetNonceLength()));
	}

	if (EVP_EncryptInit_ex(_ctx, NULL, NULL, reinterpret_cast<unsigned char*>(key), reinterpret_cast<unsigned char*>(iv)) != 1)
	{
		throw std::runtime_error("Failed to set KEY and IV in the cipher context.");
	}
}


void EncrypterGCM::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterGCM::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}


void EncrypterGCM::SetKey(void* key, void* iv, void* aad, size_t len)
{
	DEBUG("#EncrypterGCM::SetKey(k,i,a)\n");
	SetKeyIv(key, iv);
	_aad = ByteString(aad, len);
}


ByteString EncrypterGCM::Update(void* inputBuffer, size_t inputLength)
{
	if (_aad)
	{
		int length = -1;
		DEBUG("#EncrypterGCM::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad).Ptr());
		if (EVP_EncryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
		{
			throw std::runtime_error("Failed to set AAD in the cipher context.");
		}
		_aad = ByteString(); // to clear
	}

	return Encrypter::Update(inputBuffer, inputLength);
}
