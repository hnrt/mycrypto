// Copyright (C) 2026 Hideaki Narita


#include "DecrypterCTR.h"
#include "Decrypter.h"
#include "CipherMode.h"
#include "Debug.h"


using namespace hnrt;


DecrypterCTR::DecrypterCTR(CipherMode cm)
	: Decrypter(cm)
{
	DEBUG("#DecrypterCTR::ctor\n");
}


DecrypterCTR::~DecrypterCTR()
{
	DEBUG("#DecrypterCTR::dtor\n");
}


void DecrypterCTR::SetKey(void* key, void* iv)
{
	DEBUG("#DecrypterCTR::SetKey(k,i)\n");
	SetKeyIv(key, iv);
}
