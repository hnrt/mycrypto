// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DECRYPTERGCM_H
#define MYCRYPTO_DECRYPTERGCM_H

#include "Decrypter.h"
#include "CipherMode.h"
#include "ByteString.h"
#include <stddef.h>

namespace hnrt
{
	class DecrypterGCM
		: public Decrypter
	{
	public:

		DecrypterGCM(CipherMode cm);
		DecrypterGCM(const DecrypterGCM& src) = delete;
		virtual ~DecrypterGCM();
		virtual int GetNonceLength() const;
		virtual void SetNonceLength(int len);
		virtual int GetTagLength() const;
		virtual void SetTagLength(int len);
		virtual void SetKey(void* key, void* iv, void* tag);
		virtual void SetKey(void* key, void* iv, void* tag, void* aad, size_t len);
		virtual ByteString Update(void* inputBuffer, size_t inputLength);

	private:

		int _nonceLength;
		int _tagLength;
		ByteString _aad;
	};
}

#endif //!MYCRYPTO_DECRYPTERGCM_H
