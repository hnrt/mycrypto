// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCFB1.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCFB1::EncrypterCFB1(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCFB1::ctor\n");
}


EncrypterCFB1::~EncrypterCFB1()
{
	DEBUG("#EncrypterCFB1::dtor\n");
}


void EncrypterCFB1::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCFB1::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
