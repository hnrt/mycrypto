// Copyright (C) 2026 Hideaki Narita


#include "EncrypterOFB.h"
#include "Encrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


EncrypterOFB::EncrypterOFB(CipherMode cm)
	: Encrypter(cm)
{
	DEBUG("#EncrypterOFB::ctor\n");
}


EncrypterOFB::~EncrypterOFB()
{
	DEBUG("#EncrypterOFB::dtor\n");
}


void EncrypterOFB::SetKey(void* key, void* iv)
{
	DEBUG("#EncrypterOFB::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
