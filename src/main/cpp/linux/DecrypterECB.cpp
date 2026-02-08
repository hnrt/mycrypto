// Copyright (C) 2026 Hideaki Narita


#include "DecrypterECB.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"
#include <openssl/evp.h>
#include <stdexcept>


using namespace hnrt;


DecrypterECB::DecrypterECB(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterECB::ctor\n");
}


DecrypterECB::~DecrypterECB()
{
	DEBUG("#DecrypterECB::dtor\n");
}


void DecrypterECB::SetKey(void* key)
{
	DEBUG("#DecrypterECB::SetKey(k)\n");
	if (EVP_DecryptInit_ex(_ctx, GetAlgorithm(), NULL, reinterpret_cast<unsigned char*>(key), NULL) != 1)
	{
		throw std::runtime_error("Failed to initialize the cipher context.");
	}
}
