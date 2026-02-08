// Copyright (C) 2026 Hideaki Narita


#include "Digest.h"
#include "DigestMode.h"
#include "DigestPlatform.h"
#include "Debug.h"


using namespace hnrt;


Digest::Digest(DigestMode dm)
	: _r(1)
	, _dm(dm)
{
	DEBUG("#Digest@%s::ctor\n", DigestModeText(_dm));
}


Digest::~Digest()
{
	DEBUG("#Digest@%s::dtor\n", DigestModeText(_dm));
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
