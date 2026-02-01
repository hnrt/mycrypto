// Copyright (C) 2026 Hideaki Narita


#include "Digest.h"
#include "DigestPlatform.h"
#include "Debug.h"


using namespace hnrt;


Digest::Digest(DigestMode dm)
	: _r(1)
	, _dm(dm)
{
	DEBUG("#Digest::ctor\n");
}


Digest::~Digest()
{
	DEBUG("#Digest::dtor\n");
}


Digest* Digest::AddRef()
{
	_r++;
	return this;
}


void Digest::Release()
{
	if (--_r <= 0)
	{
		delete this;
	}
}


Digest* Digest::CreateInstance(DigestMode dm)
{
	return new DigestPlatform(dm);
}
