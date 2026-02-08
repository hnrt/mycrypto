// Copyright (C) 2026 Hideaki Narita


#include "Cipher.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "Encrypter.h"
#include "EncrypterCBC.h"
#include "EncrypterCCM.h"
#if defined(LINUX)
#include "EncrypterCFB1.h"
#include "EncrypterCFB128.h"
#include "EncrypterCFB8.h"
#elif defined(WIN32)
#include "EncrypterCFB8.h"
#endif
#include "EncrypterECB.h"
#include "EncrypterGCM.h"
#include "Decrypter.h"
#include "DecrypterCBC.h"
#include "DecrypterCCM.h"
#if defined(LINUX)
#include "DecrypterCFB1.h"
#include "DecrypterCFB128.h"
#include "DecrypterCFB8.h"
#elif defined(WIN32)
#include "DecrypterCFB8.h"
#endif
#include "DecrypterECB.h"
#include "DecrypterGCM.h"
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
	switch (cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterECB(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterECB(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCBC(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCBC(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
#if defined(LINUX)
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB1(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB1(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
#endif
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB8(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB8(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
#if defined(LINUX)
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB128(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB128(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
#endif
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCCM(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCCM(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterGCM(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterGCM(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	default:
		throw std::runtime_error("Cipher not implemented.");
	}
}
