// Copyright (C) 2026 Hideaki Narita

#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include "Array.h"
#include "StringEx.h"

namespace hnrt
{
	class BCryptHandle
	{
	public:

		BCryptHandle(BCRYPT_HANDLE = nullptr);
		BCryptHandle(const BCryptHandle&) = delete;
		virtual ~BCryptHandle() = default;
		void operator =(const BCryptHandle&) = delete;
		operator BCRYPT_HANDLE() const;

	protected:

		String GetPropertyString(PCWSTR) const;
		DWORD GetPropertyDWORD(PCWSTR) const;
		Array<DWORD> GetPropertyArrayDWORD(PCWSTR) const;
		Array<DWORD> GetPropertyKeyLengths(PCWSTR) const;
		void SetProperty(PCWSTR, PCWSTR) const;

		BCRYPT_HANDLE _h;
	};

	inline BCryptHandle::BCryptHandle(BCRYPT_HANDLE h)
		: _h(h)
	{
	}

	inline BCryptHandle::operator BCRYPT_HANDLE() const
	{
		return _h;
	}

	String BCryptErrorLabel(NTSTATUS);
}
