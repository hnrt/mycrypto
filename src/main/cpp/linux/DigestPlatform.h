// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DIGESTPLATFORM_H
#define MYCRYPTO_DIGESTPLATFORM_H

#include "Digest.h"
#include "DigestMode.h"
#include "ByteString.h"
#include <openssl/evp.h>
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

		EVP_MD_CTX* _ctx;
	};
}

#endif //!MYCRYPTO_DIGESTPLATFORM_H
