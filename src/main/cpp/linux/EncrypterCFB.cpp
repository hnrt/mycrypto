// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCFB.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCFB::EncrypterCFB(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCFB::ctor\n");
}


EncrypterCFB::~EncrypterCFB()
{
	DEBUG("#EncrypterCFB::dtor\n");
}


void EncrypterCFB::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCFB::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
