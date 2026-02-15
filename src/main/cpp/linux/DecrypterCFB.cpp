// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCFB.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCFB::DecrypterCFB(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCFB::ctor\n");
}


DecrypterCFB::~DecrypterCFB()
{
	DEBUG("#DecrypterCFB::dtor\n");
}


void DecrypterCFB::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCFB::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
