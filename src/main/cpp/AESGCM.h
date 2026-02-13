// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_AES_GCM_H
#define MYCRYPTO_AES_GCM_H

#include "StringEx.h"
#include <stdexcept>

#define AES_GCM_NONCE_LENGTH_DEFAULT 12
#define AES_GCM_NONCE_LENGTH_MIN 12
#define AES_GCM_NONCE_LENGTH_MAX 12

#define AES_GCM_TAG_LENGTH_DEFAULT 16
#define AES_GCM_TAG_LENGTH_MIN 12
#define AES_GCM_TAG_LENGTH_MAX 16

namespace hnrt
{
	namespace aes_gcm
	{
		inline void SetNonceLength(int& target, int len)
		{
			if (AES_GCM_NONCE_LENGTH_MIN <= len && len <= AES_GCM_NONCE_LENGTH_MAX)
			{
				target = len;
			}
			else
			{
				throw std::runtime_error(String::Format("Nonce length is not valid. Only %d is supported.", AES_GCM_NONCE_LENGTH_DEFAULT));
			}
		}

		inline void SetTagLength(int& target, int len)
		{
			if (AES_GCM_TAG_LENGTH_MIN <= len && len <= AES_GCM_TAG_LENGTH_MAX)
			{
				target = len;
			}
			else
			{
				throw std::runtime_error(String::Format("Tag length is not valid. The acceptable lengths are from %d to %d.", AES_GCM_TAG_LENGTH_MIN, AES_GCM_TAG_LENGTH_MAX));
			}
		}
	}
}

#endif //!MYCRYPTO_AES_GCM_H
