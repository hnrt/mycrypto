// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DIGESTMODE_H
#define MYCRYPTO_DIGESTMODE_H

namespace hnrt
{
	enum DigestMode
	{
		DIGEST_UNSPECIFIED = 0,
		MD5 = 65537,
		SHA1,
		SHA256,
		SHA384,
		SHA512
	};
}

#endif //!MYCRYPTO_DIGESTMODE_H
