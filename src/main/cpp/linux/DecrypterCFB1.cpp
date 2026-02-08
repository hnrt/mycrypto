// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCFB1.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCFB1::DecrypterCFB1(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCFB1::ctor\n");
}


DecrypterCFB1::~DecrypterCFB1()
{
	DEBUG("#DecrypterCFB1::dtor\n");
}


void DecrypterCFB1::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCFB1::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
