// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_AES_CCM_H
#define MYCRYPTO_AES_CCM_H

#include "StringEx.h"
#include <stdexcept>

#define AES_CCM_NONCE_LENGTH_DEFAULT 7
#define AES_CCM_NONCE_LENGTH_MIN 7
#define AES_CCM_NONCE_LENGTH_MAX 13

#define AES_CCM_TAG_LENGTH_DEFAULT 12
#define AES_CCM_TAG_LENGTH_MIN 8
#define AES_CCM_TAG_LENGTH_MAX 16
#define AES_CCM_TAG_LENGTH_STEP 4

namespace hnrt
{
	namespace aes_ccm
	{
		inline void SetNonceLength(int& target, int len)
		{
			if (AES_CCM_NONCE_LENGTH_MIN <= len && len <= AES_CCM_NONCE_LENGTH_MAX)
			{
				target = len;
			}
			else
			{
				throw std::runtime_error(String::Format("Nonce length is not valid. The acceptable lengths are from %d to %d.", AES_CCM_NONCE_LENGTH_MIN, AES_CCM_NONCE_LENGTH_MAX));
			}
		}

		inline void SetTagLength(int& target, int len)
		{
			if (AES_CCM_TAG_LENGTH_MIN <= len && len <= AES_CCM_TAG_LENGTH_MAX && (len % AES_CCM_TAG_LENGTH_STEP) == 0)
			{
				target = len;
			}
			else
			{
				throw std::runtime_error(String::Format("Tag length is not valid. The acceptable lengths are multiples of %d, at least %d and at most %d.", AES_CCM_TAG_LENGTH_STEP, AES_CCM_TAG_LENGTH_MIN, AES_CCM_TAG_LENGTH_MAX));
			}
		}
	}
}

#endif //!MYCRYPTO_AES_CCM_H
