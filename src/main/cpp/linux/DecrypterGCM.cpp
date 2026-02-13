// Copyright (C) 2026 Hideaki Narita


#include "DecrypterGCM.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "AESGCM.h"
#include "ByteString.h"
#include "StringEx.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdexcept>


using namespace hnrt;


DecrypterGCM::DecrypterGCM(CipherMode cm)
	: Decrypter(cm)
	, _nonceLength(AES_GCM_NONCE_LENGTH_DEFAULT)
	, _tagLength(AES_GCM_TAG_LENGTH_DEFAULT)
	, _aad()
{
	DEBUG("#DecrypterGCM::ctor\n");
}


DecrypterGCM::~DecrypterGCM()
{
	DEBUG("#DecrypterGCM::dtor\n");
}


int DecrypterGCM::GetNonceLength() const
{
	return _nonceLength;
}


void DecrypterGCM::SetNonceLength(int len)
{
	aes_gcm::SetNonceLength(_nonceLength, len);
}


int DecrypterGCM::GetTagLength() const
{
	return _tagLength;
}


void DecrypterGCM::SetTagLength(int len)
{
	aes_gcm::SetTagLength(_tagLength, len);
}


void DecrypterGCM::SetKey(void* key, void* iv, void* tag)
{
	DEBUG("#DecrypterGCM::SetKey(k,i,t)\n");
	SetKeyIvTag(key, iv, tag);
}


void DecrypterGCM::SetKey(void* key, void* iv, void* tag, void* aad, size_t len)
{
	DEBUG("#DecrypterGCM::SetKey(k,i,t,a)\n");
	SetKeyIvTag(key, iv, tag);
	_aad = ByteString(aad, len);
}


ByteString DecrypterGCM::Update(void* inputBuffer, size_t inputLength)
{
	if (_aad)
	{
		int length = -1;
		DEBUG("#DecrypterGCM::Update(%zu): AAD=[%zu]{%s}\n", inputLength, _aad.Length(), String::Hex(_aad).Ptr());
		if (EVP_DecryptUpdate(_ctx, NULL, &length, reinterpret_cast<unsigned char*>(_aad.Ptr()), static_cast<int>(_aad.Length())) != 1)
		{
			throw std::runtime_error("Failed to set AAD in the cipher context.");
		}
		_aad = ByteString();
	}

	return Decrypter::Update(inputBuffer, inputLength);
}
