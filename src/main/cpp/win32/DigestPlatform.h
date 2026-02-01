// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "Digest.h"
#include "DigestMode.h"
#include "ByteString.h"
#include "BCryptAlgHandle.h"
#include "BCryptHashHandle.h"
#include <stddef.h>

namespace hnrt
{
	class DigestPlatform
		: public Digest
	{
	public:

		DigestPlatform(DigestMode dm);
		DigestPlatform(const DigestPlatform&) = delete;
		virtual ~DigestPlatform();
		virtual int GetLength() const;
		virtual void Update(const void* ptr, size_t len);
		virtual ByteString Finalize();

	private:

		BCryptAlgHandle _hA;
		BCryptHashHandle _h;
		int _length;
	};
}
