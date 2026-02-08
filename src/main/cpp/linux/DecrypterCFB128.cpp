// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCFB128.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCFB128::DecrypterCFB128(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCFB128::ctor\n");
}


DecrypterCFB128::~DecrypterCFB128()
{
	DEBUG("#DecrypterCFB128::dtor\n");
}


void DecrypterCFB128::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCFB128::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
