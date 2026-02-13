// Copyright (C) 2026 Hideaki Narita


#include "Cipher.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "AES.h"
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
	if (IsAES(_cm))
	{
		return CipherModeToKeyLength(_cm);
	}
	else
	{
		throw std::runtime_error("Bad cipher mode.");
	}
}


int Cipher::GetIvLength() const
{
	if (IsAES(_cm))
	{
		return AES_BLOCK_LENGTH;
	}
	else
	{
		throw std::runtime_error("Bad cipher mode.");
	}
}


int Cipher::GetNonceLength() const
{
	return 0;
}


void Cipher::SetNonceLength(int len)
{
	throw std::runtime_error("Nonce is not available.");
}


int Cipher::GetTagLength() const
{
	return 0;
}


void Cipher::SetTagLength(int len)
{
	throw std::runtime_error("Tag is not available.");
}
