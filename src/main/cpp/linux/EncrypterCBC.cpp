// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCBC.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCBC::EncrypterCBC(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCBC::ctor\n");
}


EncrypterCBC::~EncrypterCBC()
{
	DEBUG("#EncrypterCBC::dtor\n");
}


void EncrypterCBC::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCBC::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
