// Copyright (C) 2026 Hideaki Narita


#include "CipherPlatform.h"
#include "Cipher.h"
#include "CipherMode.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


CipherPlatform::CipherPlatform(CipherMode cm)
	: Cipher(cm)
	, _ctx(EVP_CIPHER_CTX_new())
{
	DEBUG("#CipherPlatform::ctor\n");
	if (!_ctx)
	{
		throw std::bad_alloc();
	}
}


CipherPlatform::~CipherPlatform()
{
	DEBUG("#CipherPlatform::dtor\n");
	if (_ctx)
	{
		EVP_CIPHER_CTX_free(_ctx);
	}
}


const EVP_CIPHER* CipherPlatform::GetAlgorithm()
{
	switch (_cm)
	{
	case CipherMode::AES_128_ECB:
		return EVP_aes_128_ecb();
	case CipherMode::AES_192_ECB:
		return EVP_aes_192_ecb();
	case CipherMode::AES_256_ECB:
		return EVP_aes_256_ecb();
	case CipherMode::AES_128_CBC:
		return EVP_aes_128_cbc();
	case CipherMode::AES_192_CBC:
		return EVP_aes_192_cbc();
	case CipherMode::AES_256_CBC:
		return EVP_aes_256_cbc();
	case CipherMode::AES_128_CFB1:
		return EVP_aes_128_cfb1();
	case CipherMode::AES_192_CFB1:
		return EVP_aes_192_cfb1();
	case CipherMode::AES_256_CFB1:
		return EVP_aes_256_cfb1();
	case CipherMode::AES_128_CFB8:
		return EVP_aes_128_cfb8();
	case CipherMode::AES_192_CFB8:
		return EVP_aes_192_cfb8();
	case CipherMode::AES_256_CFB8:
		return EVP_aes_256_cfb8();
	case CipherMode::AES_128_CFB128:
		return EVP_aes_128_cfb128();
	case CipherMode::AES_192_CFB128:
		return EVP_aes_192_cfb128();
	case CipherMode::AES_256_CFB128:
		return EVP_aes_256_cfb128();
	case CipherMode::AES_128_OFB:
		return EVP_aes_128_ofb();
	case CipherMode::AES_192_OFB:
		return EVP_aes_192_ofb();
	case CipherMode::AES_256_OFB:
		return EVP_aes_256_ofb();
	case CipherMode::AES_128_CTR:
		return EVP_aes_128_ctr();
	case CipherMode::AES_192_CTR:
		return EVP_aes_192_ctr();
	case CipherMode::AES_256_CTR:
		return EVP_aes_256_ctr();
	case CipherMode::AES_128_CCM:
		return EVP_aes_128_ccm();
	case CipherMode::AES_192_CCM:
		return EVP_aes_192_ccm();
	case CipherMode::AES_256_CCM:
		return EVP_aes_256_ccm();
	case CipherMode::AES_128_GCM:
		return EVP_aes_128_gcm();
	case CipherMode::AES_192_GCM:
		return EVP_aes_192_gcm();
	case CipherMode::AES_256_GCM:
		return EVP_aes_256_gcm();
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


ByteString CipherPlatform::GetTag() const
{
	ByteString tag(GetTagLength());
	if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_GET_TAG, tag.Length(), tag) != 1)
	{
		throw std::runtime_error("Failed to get the AEAD tag.");
	}
	DEBUG("#CipherPlatform::GetTag: [%lu]{%s}\n", tag.Length(), String::Hex(tag, tag.Length()).Ptr());
	return tag;
}


String CipherPlatform::ErrorMessage()
{
	unsigned long errCode = ERR_get_error();
	char* errStr = ERR_error_string(errCode, NULL);
	return String::Format("%s", errStr ? errStr : String::Format("[ERROR %lx]", errCode).Ptr());
}
