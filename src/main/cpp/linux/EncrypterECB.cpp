// Copyright (C) 2026 Hideaki Narita


#include "EncrypterECB.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stdexcept>


using namespace hnrt;


EncrypterECB::EncrypterECB(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterECB::ctor\n");
}


EncrypterECB::~EncrypterECB()
{
	DEBUG("#EncrypterECB::dtor\n");
}


void EncrypterECB::SetKey(void* key)
{
	DEBUG("#EncrypterECB::SetKey(k)\n");
	if (EVP_EncryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}
