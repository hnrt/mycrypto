// Copyright (C) 2026 Hideaki Narita


#include "EncrypterCFB8.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterCFB8::EncrypterCFB8(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterCFB8::ctor\n");
}


EncrypterCFB8::~EncrypterCFB8()
{
	DEBUG("#EncrypterCFB8::dtor\n");
}


void EncrypterCFB8::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterCFB8::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
