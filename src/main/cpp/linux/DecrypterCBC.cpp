// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCBC.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCBC::DecrypterCBC(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCBC::ctor\n");
}


DecrypterCBC::~DecrypterCBC()
{
	DEBUG("#DecrypterCBC::dtor\n");
}


void DecrypterCBC::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCBC::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
