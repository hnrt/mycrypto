// Copyright (C) 2026 Hideaki Narita


#include "Cipher.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "Encrypter.h"
#include "Debug.h"
#include <stdexcept>


using namespace hnrt;


Cipher::Cipher(CipherMode cm)
	: _r(1)
	, _cm(cm)
{
	DEBUG("#Cipher::ctor\n");
}


Cipher::~Cipher()
{
	DEBUG("#Cipher::dtor\n");
}


Cipher* Cipher::AddRef()
{
	_r++;
	return this;
}


void Cipher::Release()
{
	if (--_r <= 0)
	{
		delete this;
	}
}


int Cipher::GetKeyLength() const
{
	switch (_cm)
	{
	case CipherMode::AES_256_GCM:
		return AES_256_KEY_LENGTH;
	default:
		throw std::runtime_error("Bad cipher mode.");
	}
}


int Cipher::GetIvLength() const
{
	switch (_cm)
	{
	case CipherMode::AES_256_GCM:
		return GCM_IV_LENGTH;
	default:
		return 0;
	}
}


int Cipher::GetTagLength() const
{
	switch (_cm)
	{
	case CipherMode::AES_256_GCM:
		return GCM_TAG_LENGTH;
	default:
		return 0;
	}
}


Cipher* Cipher::CreateInstance(CipherMode cm, OperationMode om)
{
	switch (om)
	{
	case OperationMode::ENCRYPTION:
		return new Encrypter(cm);
	default:
		throw std::runtime_error("Bad operation mode.");
	}
}
