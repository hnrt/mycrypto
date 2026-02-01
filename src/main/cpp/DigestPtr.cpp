// Copyright (C) 2026 Hideaki Narita


#include "DigestPtr.h"
#include "Digest.h"


using namespace hnrt;


DigestPtr::DigestPtr()
	: _p(nullptr)
{
}


DigestPtr::DigestPtr(const DigestPtr& src)
	: _p(src._p ? src._p->AddRef() : nullptr)
{
}


DigestPtr::~DigestPtr()
{
	if (_p)
	{
		_p->Release();
	}
}


DigestPtr& DigestPtr::operator = (const DigestPtr& src)
{
	if (_p)
	{
		_p->Release();
	}
	_p = src._p ? src._p->AddRef() : nullptr;
	return *this;
}


void DigestPtr::Initialize(DigestMode dm)
{
	if (_p)
	{
		_p->Release();
	}
	_p = Digest::CreateInstance(dm);

}


const Digest* DigestPtr::operator -> () const
{
	return _p;
}


Digest* DigestPtr::operator -> ()
{
	return _p;
}
