// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DIGESTPTR_H
#define MYCRYPTO_DIGESTPTR_H

#include "Digest.h"
#include "DigestMode.h"

namespace hnrt
{
	class DigestPtr
	{
	public:

		DigestPtr();
		DigestPtr(const DigestPtr&);
		~DigestPtr();
		DigestPtr& operator = (const DigestPtr& src);
		void Initialize(DigestMode dm);
		const Digest* operator ->() const;
		Digest* operator ->();

	private:

		Digest* _p;
	};
}

#endif //!MYCRYPTO_DIGESTPTR_H
