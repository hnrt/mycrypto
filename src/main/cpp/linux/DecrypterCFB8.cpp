// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCFB8.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCFB8::DecrypterCFB8(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCFB8::ctor\n");
}


DecrypterCFB8::~DecrypterCFB8()
{
	DEBUG("#DecrypterCFB8::dtor\n");
}


void DecrypterCFB8::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCFB8::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
