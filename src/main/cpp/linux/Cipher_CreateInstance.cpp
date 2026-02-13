// Copyright (C) 2026 Hideaki Narita


#include "Cipher.h"
#include "CipherMode.h"
#include "OperationMode.h"
#include "Encrypter.h"
#include "EncrypterCBC.h"
#include "EncrypterCCM.h"
#include "EncrypterCFB1.h"
#include "EncrypterCFB128.h"
#include "EncrypterCFB8.h"
#include "EncrypterECB.h"
#include "EncrypterGCM.h"
#include "Decrypter.h"
#include "DecrypterCBC.h"
#include "DecrypterCCM.h"
#include "DecrypterCFB1.h"
#include "DecrypterCFB128.h"
#include "DecrypterCFB8.h"
#include "DecrypterECB.h"
#include "DecrypterGCM.h"
#include "Debug.h"
#include <stdexcept>


using namespace hnrt;


Cipher* Cipher::CreateInstance(CipherMode cm, OperationMode om)
{
	switch (cm)
	{
	case CipherMode::AES_128_ECB:
	case CipherMode::AES_192_ECB:
	case CipherMode::AES_256_ECB:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterECB(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterECB(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CBC:
	case CipherMode::AES_192_CBC:
	case CipherMode::AES_256_CBC:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCBC(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCBC(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CFB1:
	case CipherMode::AES_192_CFB1:
	case CipherMode::AES_256_CFB1:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB1(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB1(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CFB8:
	case CipherMode::AES_192_CFB8:
	case CipherMode::AES_256_CFB8:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB8(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB8(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CFB128:
	case CipherMode::AES_192_CFB128:
	case CipherMode::AES_256_CFB128:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCFB128(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCFB128(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_CCM:
	case CipherMode::AES_192_CCM:
	case CipherMode::AES_256_CCM:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterCCM(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterCCM(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	case CipherMode::AES_128_GCM:
	case CipherMode::AES_192_GCM:
	case CipherMode::AES_256_GCM:
		switch (om)
		{
		case OperationMode::ENCRYPTION:
			return new EncrypterGCM(cm);
		case OperationMode::DECRYPTION:
			return new DecrypterGCM(cm);
		default:
			throw std::runtime_error("Bad operation mode.");
		}
	default:
		throw std::runtime_error("Cipher not implemented.");
	}
}
