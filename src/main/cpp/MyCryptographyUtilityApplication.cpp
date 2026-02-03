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


bool MyCryptographyUtilityApplication::SetAes128Cbc(CommandLine& args)
{
	DEBUG("#SetAes128Cbc\n");
	SetCipherMode(CipherMode::AES_128_CBC);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Cbc(CommandLine& args)
{
	DEBUG("#SetAes192Cbc\n");
	SetCipherMode(CipherMode::AES_192_CBC);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Cbc(CommandLine& args)
{
	DEBUG("#SetAes256Cbc\n");
	SetCipherMode(CipherMode::AES_256_CBC);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Ecb(CommandLine& args)
{
	DEBUG("#SetAes128Ecb\n");
	SetCipherMode(CipherMode::AES_128_ECB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Ecb(CommandLine& args)
{
	DEBUG("#SetAes192Ecb\n");
	SetCipherMode(CipherMode::AES_192_ECB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Ecb(CommandLine& args)
{
	DEBUG("#SetAes256Ecb\n");
	SetCipherMode(CipherMode::AES_256_ECB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Cfb(CommandLine& args)
{
	DEBUG("#SetAes128Cfb\n");
	SetCipherMode(CipherMode::AES_128_CFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Cfb(CommandLine& args)
{
	DEBUG("#SetAes192Cfb\n");
	SetCipherMode(CipherMode::AES_192_CFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Cfb(CommandLine& args)
{
	DEBUG("#SetAes256Cfb\n");
	SetCipherMode(CipherMode::AES_256_CFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Gcm(CommandLine& args)
{
	DEBUG("#SetAes128Gcm\n");
	SetCipherMode(CipherMode::AES_128_GCM);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Gcm(CommandLine& args)
{
	DEBUG("#SetAes192Gcm\n");
	SetCipherMode(CipherMode::AES_192_GCM);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Gcm(CommandLine& args)
{
	DEBUG("#SetAes256Gcm\n");
	SetCipherMode(CipherMode::AES_256_GCM);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Ccm(CommandLine& args)
{
	DEBUG("#SetAes128Ccm\n");
	SetCipherMode(CipherMode::AES_128_CCM);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Ccm(CommandLine& args)
{
	DEBUG("#SetAes192Ccm\n");
	SetCipherMode(CipherMode::AES_192_CCM);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Ccm(CommandLine& args)
{
	DEBUG("#SetAes256Ccm\n");
	SetCipherMode(CipherMode::AES_256_CCM);
	return true;
}


void MyCryptographyUtilityApplication::SetCipherMode(CipherMode mode)
{
	if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED)
	{
		if (_digestMode == DigestMode::DIGEST_UNSPECIFIED)
		{
			_cipherMode = mode;
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
	File inputStream;
	inputStream.OpenForRead(_inputPath);
	CipherPtr cipher;
	cipher.Initialize(_cipherMode, OperationMode::ENCRYPTION);
	if (_passphrase)
	{
		ComputeKey();
	}
	if (cipher->GetIvLength())
	{
		if (!_iv)
		{
			ComputeIv();
		}
		cipher->SetKeyAndIv(_key, _iv);
		fprintf(stdout, "KEY=%s\n", (const char*)String::Hex(_key, cipher->GetKeyLength()));
		fprintf(stdout, "IV=%s\n", (const char*)String::Hex(_iv, cipher->GetIvLength()));
	}
	else
	{
		cipher->SetKey(_key);
		fprintf(stdout, "KEY=%s\n", (const char*)String::Hex(_key, cipher->GetKeyLength()));
	}
	if (cipher->GetTagLength())
	{
		if (_aad.Ptr())
		{
			cipher->SetAdditionalAuthenticatedData(_aad, _aad.Length());
			fprintf(stdout, "AAD=%s\n", (const char*)String::Hex(_aad.Ptr(), _aad.Length()));
		}
	}
	File outputStream;
	outputStream.OpenForWrite(_outputPath);
	if (cipher->GetIvLength())
	{
		outputStream.Write(_iv, cipher->GetIvLength());
	}
	size_t inputLength = inputStream.Size(_inputPath);
	if (!inputLength)
	{
		throw std::runtime_error("Input file is empty. No content to be encrypted.");
	}
	size_t remaining = inputLength;
	unsigned char plaintext[BUFFER_SIZE];
	while (BUFFER_SIZE < remaining)
	{
		size_t plaintextLength = inputStream.Read(plaintext, BUFFER_SIZE);
		if (plaintextLength < BUFFER_SIZE)
		{
			throw std::runtime_error("Failed to read from input file.");
		}
		ByteString ciphertext = cipher->Update(plaintext, BUFFER_SIZE);
		if (ciphertext.Length() > 0)
		{
			outputStream.Write(ciphertext, ciphertext.Length());
		}
		remaining -= BUFFER_SIZE;
	}
	size_t plaintextLength = inputStream.Read(plaintext, remaining);
	if (plaintextLength < remaining)
	{
		throw std::runtime_error("Failed to read from input file.");
	}
	ByteString ciphertext = cipher->Finalize(plaintext, remaining);
	if (ciphertext.Length() > 0)
	{
		outputStream.Write(ciphertext, ciphertext.Length());
	}
	if (cipher->GetTagLength())
	{
		ByteString tag = cipher->GetTag();
		fprintf(stdout, "TAG=%s\n", (const char*)String::Hex(tag, tag.Length()));
		outputStream.Write(tag, tag.Length());
	}
	outputStream.Flush();
	outputStream.Close();
	inputStream.Close();
	fprintf(stdout, "Encrypted: %zu bytes in %zu bytes out\n", inputStream.Count(), outputStream.Count());
}


void MyCryptographyUtilityApplication::Decrypt()
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
	File inputStream;
	inputStream.OpenForRead(_inputPath);
	CipherPtr cipher;
	cipher.Initialize(_cipherMode, OperationMode::DECRYPTION);
	if (_passphrase)
	{
		ComputeKey();
	}
	size_t inputLength = inputStream.Size(_inputPath);
	size_t headerLength = cipher->GetIvLength();
	size_t footerLength = cipher->GetTagLength();
	size_t envelopeLength = headerLength + footerLength;
	if (inputLength < envelopeLength)
	{
		throw std::runtime_error("Input file too short.");
	}
	else if (inputLength == envelopeLength)
	{
		throw std::runtime_error("No encrypted content.");
	}
	ByteString tag(footerLength);
	if (footerLength)
	{
		inputStream.Seek(-static_cast<ptrdiff_t>(footerLength), SEEK_END);
		if (inputStream.Read(tag, tag.Length()) != footerLength)
		{
			throw std::runtime_error("Failed to load tag.");
		}
		inputStream.Rewind();
	}
	if (headerLength)
	{
		_iv = ByteString(headerLength);
		if (inputStream.Read(_iv, _iv.Length()) != headerLength)
		{
			throw std::runtime_error("Failed to load IV.");
		}
	}
	if (cipher->GetIvLength())
	{
		cipher->SetKeyAndIv(_key, _iv);
		fprintf(stdout, "KEY=%s\n", (const char*)String::Hex(_key, cipher->GetKeyLength()));
		fprintf(stdout, "IV=%s\n", (const char*)String::Hex(_iv, cipher->GetIvLength()));
	}
	else
	{
		cipher->SetKey(_key);
		fprintf(stdout, "KEY=%s\n", (const char*)String::Hex(_key, cipher->GetKeyLength()));
	}
	if (tag.Length())
	{
		cipher->SetTag(tag, tag.Length());
		fprintf(stdout, "TAG=%s\n", (const char*)String::Hex(tag, tag.Length()));
		if (_aad.Ptr())
		{
			cipher->SetAdditionalAuthenticatedData(_aad, _aad.Length());
			fprintf(stdout, "AAD=%s\n", (const char*)String::Hex(_aad.Ptr(), _aad.Length()));
		}
	}
	File outputStream;
	outputStream.OpenForWrite(_outputPath);
	size_t remaining = inputLength - envelopeLength;
	unsigned char ciphertext[BUFFER_SIZE];
	while (BUFFER_SIZE < remaining)
	{
		size_t ciphertextLength = inputStream.Read(ciphertext, BUFFER_SIZE);
		if (ciphertextLength < BUFFER_SIZE)
		{
			throw std::runtime_error("Failed to read from input file.");
		}
		ByteString plaintext = cipher->Update(ciphertext, BUFFER_SIZE);
		if (plaintext.Length() > 0)
		{
			outputStream.Write(plaintext, plaintext.Length());
		}
		remaining -= BUFFER_SIZE;
	}
	size_t ciphertextLength = inputStream.Read(ciphertext, remaining);
	if (ciphertextLength < remaining)
	{
		throw std::runtime_error("Failed to read from input file.");
	}
	ByteString plaintext = cipher->Finalize(ciphertext, remaining);
	if (plaintext.Length() > 0)
	{
		outputStream.Write(plaintext, plaintext.Length());
	}
	outputStream.Flush();
	outputStream.Close();
	inputStream.Close();
	fprintf(stdout, "Decrypted: %zu bytes in %zu bytes out\n", inputStream.Count(), outputStream.Count());
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
