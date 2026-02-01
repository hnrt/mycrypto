// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_CIPHERPTR_H
#define MYCRYPTO_CIPHERPTR_H

#include "CipherMode.h"
#include "OperationMode.h"
#include "Cipher.h"

namespace hnrt
{
	class CipherPtr
	{
	public:

		CipherPtr();
		CipherPtr(const CipherPtr& src);
		~CipherPtr();
		CipherPtr& operator = (const CipherPtr& src);
		void Initialize(CipherMode cm, OperationMode om);
		const Cipher* operator -> () const;
		Cipher* operator -> ();
		operator bool() const;

	private:

		Cipher* _p;
	};

	inline const Cipher* CipherPtr::operator -> () const
	{
		return _p;
	}

	inline Cipher* CipherPtr::operator -> ()
	{
		return _p;
	}

	inline CipherPtr::operator bool() const
	{
		return _p ? true : false;
	}
}

#endif //!MYCRYPTO_CIPHERPTR_H
