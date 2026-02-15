// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCTR.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCTR::EncrypterCTR(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCTR::ctor\n");
}


EncrypterCTR::~EncrypterCTR()
{
	DEBUG("#EncrypterCTR::dtor\n");
}


void EncrypterCTR::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCTR::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
