// Copyright (C) 2026 Hideaki Narita


#include "CipherPtr.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "Cipher.h"


using namespace hnrt;


CipherPtr::CipherPtr()
	: _p(nullptr)
{
}


CipherPtr::CipherPtr(const CipherPtr& src)
	: _p(src._p ? src._p->AddRef() : nullptr)
{
}


CipherPtr::~CipherPtr()
{
	if (_p)
	{
		_p->Release();
	}
}


CipherPtr& CipherPtr::operator = (const CipherPtr& src)
{
	if (_p)
	{
		_p->Release();
	}
	_p = src._p ? src._p->AddRef() : nullptr;
	return *this;
}


void CipherPtr::Initialize(CipherMode cm, OperationMode om)
{
	if (_p)
	{
		_p->Release();
	}
	_p = Cipher::CreateInstance(cm, om);
}
