// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCFB128.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCFB128::EncrypterCFB128(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCFB128::ctor\n");
}


EncrypterCFB128::~EncrypterCFB128()
{
	DEBUG("#EncrypterCFB128::dtor\n");
}


void EncrypterCFB128::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCFB128::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
