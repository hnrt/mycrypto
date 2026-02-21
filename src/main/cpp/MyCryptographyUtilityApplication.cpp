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
	, _temporaryPath()
	, _passphrase()
	, _aad()
	, _key()
	, _iv()
	, _nonce()
	, _nonceLength(0)
	, _tagLength(0)
	, _console(stdout)
	, _optionSet("Options")
	, _cipherOptionSet("Cipher options")
	, _digestOptionSet("Digest options")
{
	_optionSet
		.Add("aes-128-ecb", NULL, "cipher: AES [Electronic CodeBook] key=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes128Ecb)
		.Add("aes-192-ecb", NULL, "cipher: AES [Electronic CodeBook] key=24 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes192Ecb)
		.Add("aes-256-ecb", NULL, "cipher: AES [Electronic CodeBook] key=32 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes256Ecb)
		.Add("aes-128-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=16 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes128Cbc)
		.Add("aes-192-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=24 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes192Cbc)
		.Add("aes-256-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=32 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes256Cbc)
		.Add("aes-128-cfb", NULL, "cipher: AES [Cipher Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Cfb)
		.Add("aes-192-cfb", NULL, "cipher: AES [Cipher Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Cfb)
		.Add("aes-256-cfb", NULL, "cipher: AES [Cipher Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Cfb)
		.Add("aes-128-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Cfb8)
		.Add("aes-192-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Cfb8)
		.Add("aes-256-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Cfb8)
		.Add("aes-128-ofb", NULL, "cipher: AES [Output Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Ofb)
		.Add("aes-192-ofb", NULL, "cipher: AES [Output Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Ofb)
		.Add("aes-256-ofb", NULL, "cipher: AES [Output Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Ofb)
		.Add("aes-128-ctr", NULL, "cipher: AES [Counter Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Ctr)
		.Add("aes-192-ctr", NULL, "cipher: AES [Counter Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Ctr)
		.Add("aes-256-ctr", NULL, "cipher: AES [Counter Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Ctr)
		.Add("aes-128-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=16 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes128Ccm)
		.Add("aes-192-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=24 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes192Ccm)
		.Add("aes-256-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=32 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes256Ccm)
		.Add("aes-128-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=16 nonce=12 tag=16", &MyCryptographyUtilityApplication::SetAes128Gcm)
		.Add("aes-192-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=24 nonce=12 tag=16", &MyCryptographyUtilityApplication::SetAes192Gcm)
		.Add("aes-256-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=32 nonce=12 tag=16", &MyCryptographyUtilityApplication::SetAes256Gcm)
		.Add("md5", NULL, "digest: MD5 (16 bytes long)", &MyCryptographyUtilityApplication::SetMD5)
		.Add("sha1", NULL, "digest: SHA1 (20 bytes long)", &MyCryptographyUtilityApplication::SetSHA1)
		.Add("sha256", NULL, "digest: SHA256 (32 bytes long)", &MyCryptographyUtilityApplication::SetSHA256)
		.Add("sha384", NULL, "digest: SHA384 (48 bytes long)", &MyCryptographyUtilityApplication::SetSHA384)
		.Add("sha512", NULL, "digest: SHA512 (64 bytes long)", &MyCryptographyUtilityApplication::SetSHA512)
		.Add("help", NULL, "prints this message", &MyCryptographyUtilityApplication::Help)
		.AddAlias("-help", "help")
		.AddAlias("-h", "help");
	_cipherOptionSet
		.Add("-encrypt", NULL, "sets operation mode to encryption", &MyCryptographyUtilityApplication::SetEncryptionMode)
		.Add("-decrypt", NULL, "sets operation mode to decryption", &MyCryptographyUtilityApplication::SetDecryptionMode)
		.Add("-input", "PATH", "specifies input file path\nreads from standard input if a hyphen is specified", &MyCryptographyUtilityApplication::SetInputPath)
		.Add("-output", "PATH", "specifies output file path\nwrites to standard output if a hyphen is specified", &MyCryptographyUtilityApplication::SetOutputPath)
		.Add("-passphrase", "TEXT", "specifies passphrase to generate key", &MyCryptographyUtilityApplication::SetPassphrase)
		.Add("-key", "HEX", "specifies private key", &MyCryptographyUtilityApplication::SetKey)
		.Add("-iv", "HEX", "specifies initial vector", &MyCryptographyUtilityApplication::SetIV)
		.Add("-nonce", "HEX", "specifies nonce for AEAD", &MyCryptographyUtilityApplication::SetNonce)
		.Add("-aad", "TEXT", "specifies additional authenticated data for AEAD", &MyCryptographyUtilityApplication::SetAdditionalAuthenticatedData)
		.Add("-noncelength", "NUM", "specifies nonce length for AEAD\ndefault: ccm=7 gcm=12", &MyCryptographyUtilityApplication::SetNonceLength)
		.Add("-taglength", "NUM", "specifies tag length for AEAD\ndefault: ccm=12 gcm=16", &MyCryptographyUtilityApplication::SetTagLength)
		.Add("-help", NULL, NULL, &MyCryptographyUtilityApplication::Help)
		.AddAlias("-e", "-encrypt")
		.AddAlias("-d", "-decrypt")
		.AddAlias("-i", "-input")
		.AddAlias("-o", "-output")
		.AddAlias("-p", "-passphrase")
		.AddAlias("-k", "-key")
		.AddAlias("-v", "-iv")
		.AddAlias("-n", "-nonce")
		.AddAlias("-a", "-aad")
		.AddAlias("-N", "-noncelength")
		.AddAlias("-T", "-taglength")
		.AddAlias("-h", "-help");
	_digestOptionSet
		.Add("-input", "PATH", "specifies input file path\nreads from standard input if a hyphen is specified", &MyCryptographyUtilityApplication::SetInputPath)
		.Add("-output", "PATH", "specifies output file path\nwrites to standard output by default", &MyCryptographyUtilityApplication::SetOutputPath)
		.Add("-help", NULL, NULL, &MyCryptographyUtilityApplication::Help)
		.AddAlias("-i", "-input")
		.AddAlias("-o", "-output")
		.AddAlias("-h", "-help");
	CommandLineOptionSet::AlignFormat(&_optionSet, &_cipherOptionSet, &_digestOptionSet, nullptr);
}


MyCryptographyUtilityApplication::~MyCryptographyUtilityApplication()
{
}


bool MyCryptographyUtilityApplication::SetAes128Ecb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Ecb\n");
	SetCipherMode(CipherMode::AES_128_ECB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Ecb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Ecb\n");
	SetCipherMode(CipherMode::AES_192_ECB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Ecb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Ecb\n");
	SetCipherMode(CipherMode::AES_256_ECB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Cbc(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Cbc\n");
	SetCipherMode(CipherMode::AES_128_CBC);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Cbc(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Cbc\n");
	SetCipherMode(CipherMode::AES_192_CBC);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Cbc(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Cbc\n");
	SetCipherMode(CipherMode::AES_256_CBC);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Cfb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Cfb\n");
	SetCipherMode(CipherMode::AES_128_CFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Cfb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Cfb\n");
	SetCipherMode(CipherMode::AES_192_CFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Cfb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Cfb\n");
	SetCipherMode(CipherMode::AES_256_CFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Cfb8(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Cfb8\n");
	SetCipherMode(CipherMode::AES_128_CFB8);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Cfb8(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Cfb8\n");
	SetCipherMode(CipherMode::AES_192_CFB8);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Cfb8(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Cfb8\n");
	SetCipherMode(CipherMode::AES_256_CFB8);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Ofb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Ofb\n");
	SetCipherMode(CipherMode::AES_128_OFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Ofb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Ofb\n");
	SetCipherMode(CipherMode::AES_192_OFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Ofb(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Ofb\n");
	SetCipherMode(CipherMode::AES_256_OFB);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Ctr(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Ctr\n");
	SetCipherMode(CipherMode::AES_128_CTR);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Ctr(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Ctr\n");
	SetCipherMode(CipherMode::AES_192_CTR);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Ctr(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Ctr\n");
	SetCipherMode(CipherMode::AES_256_CTR);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Ccm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Ccm\n");
	SetCipherMode(CipherMode::AES_128_CCM);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Ccm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Ccm\n");
	SetCipherMode(CipherMode::AES_192_CCM);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Ccm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Ccm\n");
	SetCipherMode(CipherMode::AES_256_CCM);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes128Gcm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes128Gcm\n");
	SetCipherMode(CipherMode::AES_128_GCM);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes192Gcm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes192Gcm\n");
	SetCipherMode(CipherMode::AES_192_GCM);
	return _cipherOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetAes256Gcm(CommandLineIterator& iterator)
{
	DEBUG("#SetAes256Gcm\n");
	SetCipherMode(CipherMode::AES_256_GCM);
	return _cipherOptionSet.Process(*this, iterator);
}


void MyCryptographyUtilityApplication::SetCipherMode(CipherMode mode)
{
	_cipherMode = mode;
}


bool MyCryptographyUtilityApplication::SetMD5(CommandLineIterator& iterator)
{
	DEBUG("#SetMD5\n");
	SetDigestMode(DigestMode::MD5);
	return _digestOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetSHA1(CommandLineIterator& iterator)
{
	DEBUG("#SetSHA1\n");
	SetDigestMode(DigestMode::SHA1);
	return _digestOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetSHA256(CommandLineIterator& iterator)
{
	DEBUG("#SetSHA256\n");
	SetDigestMode(DigestMode::SHA256);
	return _digestOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetSHA384(CommandLineIterator& iterator)
{
	DEBUG("#SetSHA384\n");
	SetDigestMode(DigestMode::SHA384);
	return _digestOptionSet.Process(*this, iterator);
}


bool MyCryptographyUtilityApplication::SetSHA512(CommandLineIterator& iterator)
{
	DEBUG("#SetSHA512\n");
	SetDigestMode(DigestMode::SHA512);
	return _digestOptionSet.Process(*this, iterator);
}


void MyCryptographyUtilityApplication::SetDigestMode(DigestMode mode)
{
	_digestMode = mode;
	_operationMode = OperationMode::DIGEST;
}


bool MyCryptographyUtilityApplication::SetEncryptionMode(CommandLineIterator& iterator)
{
	if (_operationMode == OperationMode::ENCRYPTION || _operationMode == OperationMode::DECRYPTION)
	{
		throw std::runtime_error("Operation mode can be specified once.");
	}
	DEBUG("#SetEncryptionMode\n");
	_operationMode = OperationMode::ENCRYPTION;
	return true;
}


bool MyCryptographyUtilityApplication::SetDecryptionMode(CommandLineIterator& iterator)
{
	if (_operationMode == OperationMode::ENCRYPTION || _operationMode == OperationMode::DECRYPTION)
	{
		throw std::runtime_error("Operation mode can be specified once.");
	}
	DEBUG("#SetDecryptionMode\n");
	_operationMode = OperationMode::DECRYPTION;
	return true;
}


bool MyCryptographyUtilityApplication::SetInputPath(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-input: Value is missing.");
	}
	else if (_inputPath)
	{
		throw std::runtime_error("Input file path cannot be specified twice.");
	}
	_inputPath = iterator.Next();
	DEBUG("#SetInputPath(%s)\n", _inputPath.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetOutputPath(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-output: Value is missing.");
	}
	else if (_outputPath)
	{
		throw std::runtime_error("Output file path cannot be specified twice.");
	}
	_outputPath = iterator.Next();
	if (!IsStandardOutputMode())
	{
		_temporaryPath = String::Format("%s.%zu", _outputPath.Ptr(), static_cast<size_t>(time(NULL)));
	}
	DEBUG("#SetOutputPath(%s)\n", _outputPath.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetPassphrase(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-passphrase: Value is missing.");
	}
	else if (_passphrase)
	{
		throw std::runtime_error("Passphrase cannot be specified twice.");
	}
	_passphrase = iterator.Next();
	DEBUG("#SetPassphrase(%s)\n", _passphrase.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetKey(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-key: Value is missing.");
	}
	else if (_key)
	{
		throw std::runtime_error("Key cannot be specified twice.");
	}
	_key = ByteString::ParseHex(iterator.Next());
	DEBUG("#SetKey(%s)\n", String::Hex(_key).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetIV(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-iv: Value is missing.");
	}
	else if (_iv)
	{
		throw std::runtime_error("IV cannot be specified twice.");
	}
	_iv = ByteString::ParseHex(iterator.Next());
	DEBUG("#SetIV(%s)\n", String::Hex(_iv).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetNonce(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-nonce: Value is missing.");
	}
	else if (_nonce)
	{
		throw std::runtime_error("Nonce cannot be specified twice.");
	}
	_nonce = ByteString::ParseHex(iterator.Next());
	DEBUG("#SetNonce(%s)\n", String::Hex(_nonce).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetAdditionalAuthenticatedData(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-aad: Value is missing.");
	}
	else if (_aad)
	{
		throw std::runtime_error("AAD cannot be specified twice.");
	}
	_aad = iterator.Next();
	DEBUG("#SetAdditionalAuthenticatedData(%s)\n", _aad.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetNonceLength(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-noncelength: Value is missing.");
	}
	else if (_nonceLength > 0)
	{
		throw std::runtime_error("Nonce length cannot be specified twice.");
	}
	char* stopped = nullptr;
	_nonceLength = strtoul(iterator.Next(), &stopped, 10);
	if (iterator.Next() == const_cast<const char*>(stopped) || *stopped || _nonceLength <= 0)
	{
		throw std::runtime_error("-noncelength: Value is invalid.");
	}
	DEBUG("#SetNonceLength(%d)\n", _nonceLength);
	return true;
}


bool MyCryptographyUtilityApplication::SetTagLength(CommandLineIterator& iterator)
{
	if (!iterator.HasNext())
	{
		throw std::runtime_error("-taglength: Value is missing.");
	}
	else if (_tagLength > 0)
	{
		throw std::runtime_error("Tag length cannot be specified twice.");
	}
	char* stopped = nullptr;
	_tagLength = strtoul(iterator.Next(), &stopped, 10);
	if (iterator.Next() == const_cast<const char*>(stopped) || *stopped || _tagLength <= 0)
	{
		throw std::runtime_error("-taglength: Value is invalid.");
	}
	DEBUG("#SetTagLength(%d)\n", _tagLength);
	return true;
}


bool MyCryptographyUtilityApplication::Help(CommandLineIterator& iterator)
{
	return false;
}


bool MyCryptographyUtilityApplication::Parse(int argc, char* argv[])
{
	return _optionSet.Process(*this, argc, argv);
}


void MyCryptographyUtilityApplication::Run()
{
	switch (_operationMode)
	{
	case OperationMode::ENCRYPTION:
		Encrypt();
		break;
	case OperationMode::DECRYPTION:
		Decrypt();
		break;
	case OperationMode::DIGEST:
		ComputeDigest();
		break;
	default:
		throw std::runtime_error("Neither cipher nor digest is specified. Specify one of them at least.");
	}
}


void MyCryptographyUtilityApplication::Rollback()
{
	if (_temporaryPath && File::Exists(_temporaryPath))
	{
		DEBUG("#File::Delete(%s)\n", _temporaryPath.Ptr());
		File::Delete(_temporaryPath);
	}
}


bool MyCryptographyUtilityApplication::IsStandardInputMode() const
{
	return _inputPath && !strcmp(_inputPath, "-") ? true : false;
}


bool MyCryptographyUtilityApplication::IsStandardOutputMode() const
{
	return _outputPath && !strcmp(_outputPath, "-") ? true : false;
}


void MyCryptographyUtilityApplication::Encrypt()
{
	if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED)
	{
		throw std::runtime_error("Cipher is not specified.");
	}
	if (!_inputPath)
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	if (!_outputPath)
	{
		throw std::runtime_error("Output file path is not specified.");
	}

	_console = IsStandardOutputMode() ? stderr : stdout;

	CipherPtr cipher;
	cipher.Initialize(_cipherMode, OperationMode::ENCRYPTION);

	VerifyKey(cipher);

	VerifyIV(cipher, true);

	File inputStream;
	if (IsStandardInputMode())
	{
		inputStream.OpenForRead();
	}
	else
	{
		if (!File::Exists(_inputPath))
		{
			throw std::runtime_error(String::Format("Input file is not found: %s", _inputPath.Ptr()));
		}
		inputStream.OpenForRead(_inputPath);
	}

	File outputStream;
	if (IsStandardOutputMode())
	{
		outputStream.OpenForWrite();
	}
	else
	{
		if (File::Exists(_outputPath))
		{
			throw std::runtime_error(String::Format("Output file already exists: %s", _outputPath.Ptr()));
		}
		outputStream.OpenForWrite(_temporaryPath);
	}

	if (cipher->GetNonceLength())
	{
		if (_aad)
		{
			cipher->SetKey(_key, _nonce, _aad.Ptr(), _aad.Length());
		}
		else
		{
			cipher->SetKey(_key, _nonce);
		}
		outputStream.Write(_nonce, _nonce.Length());
	}
	else if (cipher->GetIvLength())
	{
		cipher->SetKey(_key, _iv);
		outputStream.Write(_iv, _iv.Length());
	}
	else
	{
		cipher->SetKey(_key);
	}

	unsigned char plaintext[2][BUFFER_SIZE];
	size_t current = 0;
	size_t plaintextLength = inputStream.Read(plaintext[current], BUFFER_SIZE);
	if (!plaintextLength)
	{
		throw std::runtime_error("Input file is empty. No content is to be encrypted.");
	}
	while (plaintextLength == BUFFER_SIZE)
	{
		plaintextLength = inputStream.Read(plaintext[current ^ 1], BUFFER_SIZE);
		if (!plaintextLength)
		{
			plaintextLength = BUFFER_SIZE;
			break;
		}
		ByteString ciphertext = cipher->Update(plaintext[current], BUFFER_SIZE);
		if (ciphertext.Length() > 0)
		{
			outputStream.Write(ciphertext, ciphertext.Length());
		}
		current ^= 1;
	}
	ByteString ciphertext = cipher->Finalize(plaintext[current], plaintextLength);
	if (ciphertext.Length() > 0)
	{
		outputStream.Write(ciphertext, ciphertext.Length());
	}
	ByteString tag;
	if (cipher->GetTagLength())
	{
		tag = cipher->GetTag();
		outputStream.Write(tag, tag.Length());
	}

	outputStream.Flush();
	outputStream.Close();
	inputStream.Close();

	PrintCipherResult(tag, inputStream, outputStream);

	if (_temporaryPath)
	{
		File::Rename(_temporaryPath, _outputPath);
	}
}


void MyCryptographyUtilityApplication::Decrypt()
{
	if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED)
	{
		throw std::runtime_error("Cipher is not specified.");
	}
	if (!_inputPath)
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	if (!_outputPath)
	{
		throw std::runtime_error("Output file path is not specified.");
	}

	_console = IsStandardOutputMode() ? stderr : stdout;

	CipherPtr cipher;
	cipher.Initialize(_cipherMode, OperationMode::DECRYPTION);

	VerifyKey(cipher);

	VerifyIV(cipher);

	File inputStream;
	if (IsStandardInputMode())
	{
		ReadOnceFromStandardInput(inputStream);
	}
	else
	{
		if (!File::Exists(_inputPath))
		{
			throw std::runtime_error(String::Format("Input file is not found: %s", _inputPath.Ptr()));
		}
		inputStream.OpenForRead(_inputPath);
	}

	File outputStream;
	if (IsStandardOutputMode())
	{
		outputStream.OpenForWrite();
	}
	else
	{
		if (File::Exists(_outputPath))
		{
			throw std::runtime_error(String::Format("Output file already exists: %s", _outputPath.Ptr()));
		}
		outputStream.OpenForWrite(_temporaryPath);
	}

	size_t inputLength = inputStream.Size();
	size_t headerLength = _nonce ? 0 : _iv ? 0 : cipher->GetNonceLength() ? cipher->GetNonceLength() : cipher->GetIvLength();
	size_t footerLength = cipher->GetTagLength();
	size_t envelopeLength = headerLength + footerLength;
	if (inputLength < envelopeLength)
	{
		throw std::runtime_error(String::Format("Input file is too short. Envelope=%zu Actual=%zu", envelopeLength, inputLength));
	}
	else if (inputLength == envelopeLength)
	{
		throw std::runtime_error("No encrypted content.");
	}
	size_t payloadLength = inputLength - envelopeLength;
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
		ByteString header(headerLength);
		if (inputStream.Read(header, header.Length()) != header.Length())
		{
			throw std::runtime_error(cipher->GetNonceLength() ? "Failed to load nonce." : "Failed to load IV.");
		}
		else if (cipher->GetNonceLength())
		{
			_nonce = header;
		}
		else
		{
			_iv = header;
		}
	}

	if (cipher->GetNonceLength())
	{
		if (_aad)
		{
			cipher->SetKey(_key, _nonce, tag, _aad, _aad.Length());
		}
		else
		{
			cipher->SetKey(_key, _nonce, tag);
		}
	}
	else if (cipher->GetIvLength())
	{
		cipher->SetKey(_key, _iv);
	}
	else
	{
		cipher->SetKey(_key);
	}

	size_t remaining = payloadLength;
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

	PrintCipherResult(tag, inputStream, outputStream);

	if (_temporaryPath)
	{
		File::Rename(_temporaryPath, _outputPath);
	}
}


void MyCryptographyUtilityApplication::VerifyKey(const CipherPtr& cipher)
{
	if (!_key && !_passphrase)
	{
		throw std::runtime_error("Neither key nor passphrase is specified. Specify one or the other.");
	}
	else if (_key && _passphrase)
	{
		throw std::runtime_error("Both key and passphrase are specified at the same time. Specify one or the other.");
	}
	else if (_passphrase)
	{
		ComputeKey(cipher);
	}
	else if (static_cast<size_t>(cipher->GetKeyLength()) != _key.Length())
	{
		throw std::runtime_error(String::Format("Key is not valid in length. Expected=%d Actual=%zu", cipher->GetKeyLength(), _key.Length()));
	}
}


void MyCryptographyUtilityApplication::VerifyIV(CipherPtr& cipher, bool generateIfNotSpecified)
{
	if (cipher->GetIvLength())
	{
		if (_iv)
		{
			if (static_cast<size_t>(cipher->GetIvLength()) != _iv.Length())
			{
				throw std::runtime_error(String::Format("IV is not valid in length. Expected=%d Actual=%zu", cipher->GetIvLength(), _iv.Length()));
			}
		}
		else if (generateIfNotSpecified)
		{
			ComputeIV(cipher);
		}
	}
	else if (_iv)
	{
		throw std::runtime_error("IV cannot be specified for the target cipher.");
	}
}


void MyCryptographyUtilityApplication::VerifyNonce(CipherPtr& cipher, bool generateIfNotSpecified)
{
	if (cipher->GetNonceLength())
	{
		if (_nonceLength)
		{
			cipher->SetNonceLength(_nonceLength);
		}
		if (_nonce)
		{
			if (static_cast<size_t>(cipher->GetNonceLength()) != _nonce.Length())
			{
				throw std::runtime_error(String::Format("Nonce is not valid in length. Expected=%d Actual=%zu", cipher->GetNonceLength(), _nonce.Length()));
			}
		}
		else if (generateIfNotSpecified)
		{
			ComputeNonce(cipher);
		}
		if (_tagLength)
		{
			cipher->SetTagLength(_tagLength);
		}
	}
	else if (_nonce)
	{
		throw std::runtime_error("Nonce cannot be specified for the target cipher.");
	}
	else if (_nonceLength)
	{
		throw std::runtime_error("Nonce length cannot be specified for the target cipher.");
	}
	else if (_aad)
	{
		throw std::runtime_error("AAD cannot be specified for the target cipher.");
	}
	else if (_tagLength)
	{
		throw std::runtime_error("Tag length cannot be specified for the target cipher.");
	}
}


void MyCryptographyUtilityApplication::ReadOnceFromStandardInput(File& inputStream)
{
	inputStream.OpenTemporary();
	File stdinStream;
	stdinStream.OpenForRead();
	while (true)
	{
		unsigned char buffer[BUFFER_SIZE];
		size_t length = stdinStream.Read(buffer, BUFFER_SIZE);
		DEBUG("#Read from %s: %zu\n", stdinStream.Path(), length);
		if (length > 0)
		{
			inputStream.Write(buffer, length);
		}
		if (length < BUFFER_SIZE)
		{
			break;
		}
	}
	stdinStream.Close();
	inputStream.Flush();
	DEBUG("#Wrote to %s: %zu\n", inputStream.Path(), inputStream.Count());
	inputStream.Rewind();
}


void MyCryptographyUtilityApplication::ComputeKey(const CipherPtr& cipher)
{
	size_t keyLength = cipher->GetKeyLength();
	if (keyLength > 32)
	{
		DigestPtr sha512;
		sha512.Initialize(DigestMode::SHA512);
		sha512->Update((const char*)_passphrase, _passphrase.Length());
		_key = sha512->Finalize();
	}
	else
	{
		DigestPtr sha256;
		sha256.Initialize(DigestMode::SHA256);
		sha256->Update((const char*)_passphrase, _passphrase.Length());
		_key = sha256->Finalize();
	}
	if (_key.Length() < keyLength)
	{
		throw std::runtime_error("Generated key is too short for the target cipher.");
	}
	else if (_key.Length() > keyLength)
	{
		_key = ByteString(_key, keyLength);
	}
}


void MyCryptographyUtilityApplication::ComputeIV(const CipherPtr& cipher)
{
	static const char salt[] = "no way";
	size_t ivLength = cipher->GetIvLength();
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
	if (_iv.Length() < ivLength)
	{
		throw std::runtime_error("Generated IV is too short for the target cipher.");
	}
	else if (_iv.Length() > ivLength)
	{
		_iv = ByteString(_iv, ivLength);
	}
}


void MyCryptographyUtilityApplication::ComputeNonce(const CipherPtr& cipher)
{
	static const char salt[] = "so what";
	size_t nonceLength = cipher->GetNonceLength();
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
	_nonce = md5->Finalize();
	if (_nonce.Length() < nonceLength)
	{
		throw std::runtime_error("Generated nonce is too short for the target cipher.");
	}
	else if (_nonce.Length() > nonceLength)
	{
		_nonce = ByteString(_nonce, nonceLength);
	}
}


void MyCryptographyUtilityApplication::PrintCipherResult(const ByteString& tag, const File& inputStream, const File& outputStream)
{
	if (_aad)
	{
		fprintf(_console, "%10s %s\n", "KEY", String::Hex(_key).Ptr());
		fprintf(_console, "%10s %s\n", "NONCE", String::Hex(_nonce).Ptr());
		fprintf(_console, "%10s %s\n", "AAD", String::Hex(_aad, _aad.Length()).Ptr());
		fprintf(_console, "%10s %s\n", "TAG", String::Hex(tag).Ptr());
	}
	else if (tag)
	{
		fprintf(_console, "%10s %s\n", "KEY", String::Hex(_key).Ptr());
		fprintf(_console, "%10s %s\n", "NONCE", String::Hex(_nonce).Ptr());
		fprintf(_console, "%10s %s\n", "TAG", String::Hex(tag).Ptr());
	}
	else if (_iv)
	{
		fprintf(_console, "%10s %s\n", "KEY", String::Hex(_key).Ptr());
		fprintf(_console, "%10s %s\n", "IV", String::Hex(_iv).Ptr());
	}
	else
	{
		fprintf(_console, "%10s %s\n", "KEY", String::Hex(_key).Ptr());
	}
	fprintf(_console, "%10zu bytes in\n%10zu bytes out\n", inputStream.Count(), outputStream.Count());
}


void MyCryptographyUtilityApplication::ComputeDigest()
{
	if (!_inputPath)
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
	String hex = String::Lowercase(String::Hex(result));
	fprintf(stdout, "%s\n", hex.Ptr());
}


void MyCryptographyUtilityApplication::Help(const char* arg0)
{
	arg0 = strchr(arg0, DIRECTORY_SEPARATOR_CHAR) ? strrchr(arg0, DIRECTORY_SEPARATOR_CHAR) + 1 : arg0;
	fprintf(stdout, "Syntax:\n");
	fprintf(stdout, "  %s options\n", arg0);
	fprintf(stdout, "\n%s", _optionSet.ToString().Ptr());
	fprintf(stdout, "\n%s", _cipherOptionSet.ToString().Ptr());
	fprintf(stdout, "\n%s", _digestOptionSet.ToString().Ptr());
}
