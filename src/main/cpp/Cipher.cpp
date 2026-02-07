// Copyright (C) 2026 Hideaki Narita


#include "Cipher.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "Encrypter.h"
#include "Decrypter.h"
#include "Debug.h"
#include <stdexcept>


using namespace hnrt;


static int DefaultNonceLength(CipherMode cm)
{
	switch (cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		return CCM_IV_LENGTH;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return GCM_IV_LENGTH;
	default:
		return 0;
	}
}


static int DefaultTagLength(CipherMode cm)
{
	switch (cm)
	{
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		return CCM_TAG_LENGTH;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return GCM_TAG_LENGTH;
	default:
		return 0;
	}
}


Cipher::Cipher(CipherMode cm)
	: _r(1)
	, _cm(cm)
	, _nonceLength(DefaultNonceLength(cm))
	, _tagLength(DefaultTagLength(cm))
{
	DEBUG("#Cipher::ctor\n");
}


Cipher::~Cipher()
{
	DEBUG("#Cipher::dtor\n");
}


Cipher* Cipher::AddRef()
{
	_r++;
	return this;
}


void Cipher::Release()
{
	if (--_r <= 0)
	{
		delete this;
	}
}


int Cipher::GetKeyLength() const
{
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_128_OFB:
	case CipherMode::AES_128_CTR:
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_128_GCM:
		return AES_128_KEY_LENGTH;
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_192_OFB:
	case CipherMode::AES_192_CTR:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_192_GCM:
		return AES_192_KEY_LENGTH;
	case CipherMode::AES_256_ECB:
	case CipherMode::AES_256_CBC:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_256_CFB8:
	case CipherMode::AES_256_CFB128:
	case CipherMode::AES_256_OFB:
	case CipherMode::AES_256_CTR:
	case CipherMode::AES_256_CCM:
	case CipherMode::AES_256_GCM:
		return AES_256_KEY_LENGTH;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


int Cipher::GetIvLength() const
{
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		return 0;
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
	case CipherMode::AES_128_OFB:
	case CipherMode::AES_192_OFB:
	case CipherMode::AES_256_OFB:
	case CipherMode::AES_128_CTR:
	case CipherMode::AES_192_CTR:
	case CipherMode::AES_256_CTR:
		return AES_BLOCK_LENGTH;
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		return CCM_IV_LENGTH;
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		return GCM_IV_LENGTH;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


int Cipher::GetNonceLength() const
{
	return _nonceLength;
}


void Cipher::SetNonceLength(int len)
{
	if (_nonceLength)
	{
		_nonceLength = len;
	}
	else
	{
		throw std::runtime_error("Nonce is not available.");
	}
}


int Cipher::GetTagLength() const
{
	return _tagLength;
}


void Cipher::SetTagLength(int len)
{
	if (_tagLength)
	{
		_tagLength = len;
	}
	else
	{
		throw std::runtime_error("Tag is not available.");
	}
}


Cipher* Cipher::CreateInstance(CipherMode cm, OperationMode om)
{
	switch (om)
	{
	case OperationMode::ENCRYPTION:
		return new Encrypter(cm);
	case OperationMode::DECRYPTION:
		return new Decrypter(cm);
	default:
		throw std::runtime_error("Bad operation mode.");
	}
}
