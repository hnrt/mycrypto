// Copyright (C) 2026 Hideaki Narita


#include "MyCryptographyUtilityApplication.h"
#include "OperationMode.h"
#include "CipherMode.h"
#include "DigestMode.h"
#include "DigestPtr.h"
#include "CipherPtr.h"
#include "File.h"
#include "StringEx.h"
#include "ByteString.h"
#include "Debug.h"
#include <string.h>
#include <time.h>
#include <stdexcept>


#define BUFFER_SIZE 4096


using namespace hnrt;


MyCryptographyUtilityApplication::MyCryptographyUtilityApplication()
	: _operationMode(OperationMode::OPERATION_UNSPECIFIED)
	, _cipherMode(CipherMode::CIPHER_UNSPECIFIED)
	, _digestMode(DigestMode::DIGEST_UNSPECIFIED)
	, _inputPath()
	, _outputPath()
	, _passphrase()
	, _aad()
	, _key()
	, _iv()
{
}


MyCryptographyUtilityApplication::~MyCryptographyUtilityApplication()
{
}


bool MyCryptographyUtilityApplication::SetAes256Gcm(CommandLine& args)
{
	if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED)
	{
		if (_digestMode == DigestMode::DIGEST_UNSPECIFIED)
		{
			DEBUG("#SetAes256Gcm\n");
			_cipherMode = CipherMode::AES_256_GCM;
			return true;
		}
		else
		{
			throw std::runtime_error("Digest mode already specified.");
		}
	}
	else
	{
		throw std::runtime_error("Cipher mode already specified.");
	}
}


bool MyCryptographyUtilityApplication::SetMD5(CommandLine& args)
{
	DEBUG("#SetMD5\n");
	SetDigestMode(DigestMode::MD5);
	return true;
}


bool MyCryptographyUtilityApplication::SetSHA1(CommandLine& args)
{
	DEBUG("#SetSHA1\n");
	SetDigestMode(DigestMode::SHA1);
	return true;
}


bool MyCryptographyUtilityApplication::SetSHA256(CommandLine& args)
{
	DEBUG("#SetSHA256\n");
	SetDigestMode(DigestMode::SHA256);
	return true;
}


bool MyCryptographyUtilityApplication::SetSHA384(CommandLine& args)
{
	DEBUG("#SetSHA384\n");
	SetDigestMode(DigestMode::SHA384);
	return true;
}


bool MyCryptographyUtilityApplication::SetSHA512(CommandLine& args)
{
	DEBUG("#SetSHA512\n");
	SetDigestMode(DigestMode::SHA512);
	return true;
}


void MyCryptographyUtilityApplication::SetDigestMode(DigestMode mode)
{
	if (_digestMode == DigestMode::DIGEST_UNSPECIFIED)
	{
		if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED)
		{
			if (_operationMode == OperationMode::OPERATION_UNSPECIFIED)
			{
				_operationMode = OperationMode::DIGEST;
				_digestMode = mode;
			}
			else
			{
				throw std::runtime_error("Operation mode already specified.");
			}
		}
		else
		{
			throw std::runtime_error("Cipher mode already specified.");
		}
	}
	else
	{
		throw std::runtime_error("Digest mode already specified.");
	}
}


bool MyCryptographyUtilityApplication::SetEncryptionMode(CommandLine& args)
{
	if (_operationMode == OperationMode::OPERATION_UNSPECIFIED)
	{
		DEBUG("#SetEncryptionMode\n");
		_operationMode = OperationMode::ENCRYPTION;
		return true;
	}
	else if (_operationMode == OperationMode::DIGEST)
	{
		throw std::runtime_error("Digest mode already specified.");
	}
	else
	{
		throw std::runtime_error("Operation mode already specified.");
	}
}


bool MyCryptographyUtilityApplication::SetDecryptionMode(CommandLine& args)
{
	if (_operationMode == OperationMode::OPERATION_UNSPECIFIED)
	{
		DEBUG("#SetDecryptionMode\n");
		_operationMode = OperationMode::DECRYPTION;
		return true;
	}
	else if (_operationMode == OperationMode::DIGEST)
	{
		throw std::runtime_error("Digest mode already specified.");
	}
	else
	{
		throw std::runtime_error("Operation mode already specified.");
	}
}


bool MyCryptographyUtilityApplication::SetInputPath(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_inputPath.Ptr())
		{
			throw std::runtime_error(String::Format("%s: Already specified.", option).Ptr());
		}
		_inputPath = args.Argument();
		DEBUG("#SetInputPath(%s)\n", _inputPath.Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: Path is missing.", option).Ptr());
	}
	return true;
}


bool MyCryptographyUtilityApplication::SetOutputPath(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_outputPath.Ptr())
		{
			throw std::runtime_error(String::Format("%s: Already specified.", option).Ptr());
		}
		_outputPath = args.Argument();
		DEBUG("#SetOutputPath(%s)\n", _outputPath.Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: Path is missing.", option).Ptr());
	}
	return true;
}


bool MyCryptographyUtilityApplication::SetPassphrase(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_passphrase)
		{
			throw std::runtime_error(String::Format("%s: Passphrase already specified.", option).Ptr());
		}
		if (_key)
		{
			throw std::runtime_error(String::Format("%s: Key already specified.", option).Ptr());
		}
		_passphrase = args.Argument();
		DEBUG("#SetPassphrase(%s)\n", _passphrase.Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: Passphrase is missing.", option).Ptr());
	}
	return true;
}


bool MyCryptographyUtilityApplication::SetKey(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_key)
		{
			throw std::runtime_error(String::Format("%s: Key already specified.", option).Ptr());
		}
		if (_passphrase)
		{
			throw std::runtime_error(String::Format("%s: Passphrase already specified.", option).Ptr());
		}
		_key = ByteString::ParseHex(args.Argument());
		DEBUG("#SetKey(%s)\n", String::Hex(_key, _key.Length()).Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: Key is missing.", option).Ptr());
	}
	return true;
}


bool MyCryptographyUtilityApplication::SetIv(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_iv)
		{
			throw std::runtime_error(String::Format("%s: IV already specified.", option).Ptr());
		}
		_iv = ByteString::ParseHex(args.Argument());
		DEBUG("#SetIv(%s)\n", String::Hex(_iv, _iv.Length()).Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: IV is missing.", option).Ptr());
	}
	return true;
}


bool MyCryptographyUtilityApplication::SetAdditionalAuthenticatedData(CommandLine& args)
{
	const char* option = args.Argument();
	if (args.Next())
	{
		if (_aad.Ptr())
		{
			throw std::runtime_error(String::Format("%s: Already specified.", option).Ptr());
		}
		_aad = args.Argument();
		DEBUG("#SetAdditionalAuthenticatedData(%s)\n", _aad.Ptr());
	}
	else
	{
		throw std::runtime_error(String::Format("%s: Path is missing.", option).Ptr());
	}
	return true;
}


void MyCryptographyUtilityApplication::Run()
{
	switch (_operationMode)
	{
	case OperationMode::ENCRYPTION:
	case OperationMode::DECRYPTION:
		switch (_cipherMode)
		{
		case CipherMode::CIPHER_UNSPECIFIED:
			_cipherMode = CipherMode::AES_256_GCM;
			break;
		default:
			break;
		}
		switch (_operationMode)
		{
		case OperationMode::ENCRYPTION:
			Encrypt();
			break;
		case OperationMode::DECRYPTION:
			Decrypt();
			break;
		default:
			throw std::runtime_error("Bad operation mode.");
		}
		break;
	case OperationMode::DIGEST:
		ComputeDigest();
		break;
	default:
		throw std::runtime_error("Operation mode not specified.");
	}
}


void MyCryptographyUtilityApplication::Rollback()
{
}


void MyCryptographyUtilityApplication::Encrypt()
{
	if (!_inputPath)
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	if (!_outputPath)
	{
		throw std::runtime_error("Output file path is not specified.");
	}
	if (!_passphrase && !_key)
	{
		throw std::runtime_error("Passphrase/key not specified.");
	}
	if (_passphrase)
	{
		ComputeKey();
	}
	if (!_iv)
	{
		ComputeIv();
	}
	CipherPtr cipher;
	cipher.Initialize(CipherMode::AES_256_GCM, OperationMode::ENCRYPTION);
	cipher->SetKeyAndIv(_key, _iv);
	fprintf(stdout, "KEY=%s\n", (const char*)String::Hex(_key, cipher->GetKeyLength()));
	fprintf(stdout, "IV=%s\n", (const char*)String::Hex(_iv, cipher->GetIvLength()));
	if (_aad.Ptr())
	{
		cipher->SetAdditionalAuthenticatedData(_aad, _aad.Length());
		fprintf(stdout, "AAD=%s\n", (const char*)String::Hex(_aad.Ptr(), _aad.Length()));
	}
	File inputStream;
	File outputStream;
	inputStream.OpenForRead(_inputPath);
	outputStream.OpenForWrite(_outputPath);
	outputStream.Write(_iv, cipher->GetIvLength());
	size_t inputSize = inputStream.Size(_inputPath);
	size_t updateCount = inputSize ? (inputSize + BUFFER_SIZE - 1) / BUFFER_SIZE - 1 : 0;
	unsigned char plaintext[BUFFER_SIZE];
	size_t plaintextLength = 0;
	while (true)
	{
		plaintextLength += inputStream.Read(plaintext + plaintextLength, BUFFER_SIZE - plaintextLength);
		if (plaintextLength < BUFFER_SIZE)
		{
			if (feof(inputStream))
			{
				ByteString ciphertext = cipher->Finalize(plaintext, plaintextLength);
				if (ciphertext.Length() > 0)
				{
					outputStream.Write(ciphertext, ciphertext.Length());
				}
				break;
			}
			continue;
		}
		else if (!updateCount)
		{
			ByteString ciphertext = cipher->Finalize(plaintext, BUFFER_SIZE);
			if (ciphertext.Length() > 0)
			{
				outputStream.Write(ciphertext, ciphertext.Length());
			}
			break;
		}
		ByteString ciphertext = cipher->Update(plaintext, BUFFER_SIZE);
		if (ciphertext.Length() > 0)
		{
			outputStream.Write(ciphertext, ciphertext.Length());
		}
		updateCount--;
		plaintextLength = 0;
	}
	inputStream.Close();
	ByteString tag = cipher->GetTag();
	outputStream.Write(tag, tag.Length());
	outputStream.Flush();
	outputStream.Close();
	fprintf(stdout, "TAG=%s\n", (const char*)String::Hex(tag, tag.Length()));
	fprintf(stdout, "Encrypted %d bytes in %d bytes out.\n", static_cast<int>(inputStream.Count()), static_cast<int>(outputStream.Count()));
}


void MyCryptographyUtilityApplication::Decrypt()
{
}


void MyCryptographyUtilityApplication::ComputeDigest()
{
	if (!_inputPath.Ptr())
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	DigestPtr digest;
	digest.Initialize(_digestMode);
	File inputStream;
	inputStream.OpenForRead(_inputPath);
	unsigned char buffer[BUFFER_SIZE];
	while (!feof(inputStream))
	{
		size_t length = inputStream.Read(buffer, BUFFER_SIZE);
		if (length)
		{
			digest->Update(buffer, length);
		}
	}
	DEBUG("#Read %d bytes\n", static_cast<int>(inputStream.Count()));
	ByteString result = digest->Finalize();
	fprintf(stdout, "%s\n", String::Hex(result, result.Length()).Ptr());
}


void MyCryptographyUtilityApplication::ComputeKey()
{
	DigestPtr sha256;
	sha256.Initialize(DigestMode::SHA256);
	sha256->Update((const char*)_passphrase, _passphrase.Length());
	_key = sha256->Finalize();
}


void MyCryptographyUtilityApplication::ComputeIv()
{
	static const char salt[] = "no way";
	size_t saltLength = strlen(salt);
	time_t t = time(NULL);
	size_t tLength = sizeof(t);
	size_t length = saltLength + tLength;
	unsigned char tmp[256];
	memcpy(tmp, salt, saltLength);
	memcpy(tmp + saltLength, &t, tLength);
	DigestPtr md5;
	md5.Initialize(DigestMode::MD5);
	md5->Update(tmp, length);
	_iv = md5->Finalize();
}
