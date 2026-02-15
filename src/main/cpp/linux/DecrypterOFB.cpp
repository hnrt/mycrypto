// Copyright (C) 2026 Hideaki Narita


#include "DecrypterOFB.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterOFB::DecrypterOFB(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterOFB::ctor\n");
}


DecrypterOFB::~DecrypterOFB()
{
	DEBUG("#DecrypterOFB::dtor\n");
}


void DecrypterOFB::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterOFB::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
