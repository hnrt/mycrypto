// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Encrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class EncrypterCFB8
		: public Encrypter
	{
	public:

		EncrypterCFB8(CipherMode cm);
		EncrypterCFB8(const EncrypterCFB8&) = delete;
		virtual ~EncrypterCFB8();
		virtual void SetKey(void* key, void* iv);
	};
}
