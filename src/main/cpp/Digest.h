// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DIGEST_H
#define MYCRYPTO_DIGEST_H

#include "DigestMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class Digest
	{
	public:

		Digest(const Digest&) = delete;
		virtual ~Digest();
		virtual Digest* AddRef();
		virtual void Release();
		virtual int GetLength() const = 0;
		virtual void Update(const void* ptr, size_t len) = 0;
		virtual ByteString Finalize() = 0;

		static Digest* CreateInstance(DigestMode dm);

	protected:

		Digest(DigestMode dm);

		int _r;
		DigestMode _dm;
	};
}

#endif //!MYCRYPTO_DIGEST_H
