// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Decrypter.h"
#include "CipherMode.h"

namespace hnrt
{
	class DecrypterCFB8
		: public Decrypter
	{
	public:

		DecrypterCFB8(CipherMode cm);
		DecrypterCFB8(const DecrypterCFB8&) = delete;
		virtual ~DecrypterCFB8();
		virtual void SetKey(void* key, void* iv);
	};
}
