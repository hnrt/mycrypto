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
{
}


MyCryptographyUtilityApplication::~MyCryptographyUtilityApplication()
{
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


bool MyCryptographyUtilityApplication::SetAes128Cfb8(CommandLine& args)
{
	DEBUG("#SetAes128Cfb8\n");
	SetCipherMode(CipherMode::AES_128_CFB8);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Cfb8(CommandLine& args)
{
	DEBUG("#SetAes192Cfb8\n");
	SetCipherMode(CipherMode::AES_192_CFB8);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Cfb8(CommandLine& args)
{
	DEBUG("#SetAes256Cfb8\n");
	SetCipherMode(CipherMode::AES_256_CFB8);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Ofb(CommandLine& args)
{
	DEBUG("#SetAes128Ofb\n");
	SetCipherMode(CipherMode::AES_128_OFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Ofb(CommandLine& args)
{
	DEBUG("#SetAes192Ofb\n");
	SetCipherMode(CipherMode::AES_192_OFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Ofb(CommandLine& args)
{
	DEBUG("#SetAes256Ofb\n");
	SetCipherMode(CipherMode::AES_256_OFB);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes128Ctr(CommandLine& args)
{
	DEBUG("#SetAes128Ctr\n");
	SetCipherMode(CipherMode::AES_128_CTR);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes192Ctr(CommandLine& args)
{
	DEBUG("#SetAes192Ctr\n");
	SetCipherMode(CipherMode::AES_192_CTR);
	return true;
}


bool MyCryptographyUtilityApplication::SetAes256Ctr(CommandLine& args)
{
	DEBUG("#SetAes256Ctr\n");
	SetCipherMode(CipherMode::AES_256_CTR);
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


void MyCryptographyUtilityApplication::SetCipherMode(CipherMode mode)
{
	if (_cipherMode != CipherMode::CIPHER_UNSPECIFIED)
	{
		throw std::runtime_error("Cipher mode cannot be specified twice.");
	}
	else if (_digestMode != DigestMode::DIGEST_UNSPECIFIED)
	{
		throw std::runtime_error("Cipher mode cannot be specified when digest mode is specified.");
	}
	_cipherMode = mode;
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
	if (_digestMode != DigestMode::DIGEST_UNSPECIFIED)
	{
		throw std::runtime_error("Digest mode can be specified once.");
	}
	_operationMode = OperationMode::DIGEST;
	_digestMode = mode;
}


bool MyCryptographyUtilityApplication::SetEncryptionMode(CommandLine& args)
{
	if (_operationMode == OperationMode::ENCRYPTION || _operationMode == OperationMode::DECRYPTION)
	{
		throw std::runtime_error("Operation mode can be specified once.");
	}
	DEBUG("#SetEncryptionMode\n");
	_operationMode = OperationMode::ENCRYPTION;
	return true;
}


bool MyCryptographyUtilityApplication::SetDecryptionMode(CommandLine& args)
{
	if (_operationMode == OperationMode::ENCRYPTION || _operationMode == OperationMode::DECRYPTION)
	{
		throw std::runtime_error("Operation mode can be specified once.");
	}
	DEBUG("#SetDecryptionMode\n");
	_operationMode = OperationMode::DECRYPTION;
	return true;
}


bool MyCryptographyUtilityApplication::SetInputPath(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-input: Value is missing.");
	}
	else if (_inputPath)
	{
		throw std::runtime_error("Input file path cannot be specified twice.");
	}
	_inputPath = args.Argument();
	DEBUG("#SetInputPath(%s)\n", _inputPath.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetOutputPath(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-output: Value is missing.");
	}
	else if (_outputPath)
	{
		throw std::runtime_error("Output file path cannot be specified twice.");
	}
	_outputPath = args.Argument();
	if (!IsStandardOutputMode())
	{
		_temporaryPath = String::Format("%s.%zu", _outputPath.Ptr(), static_cast<size_t>(time(NULL)));
	}
	DEBUG("#SetOutputPath(%s)\n", _outputPath.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetPassphrase(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-passphrase: Value is missing.");
	}
	else if (_passphrase)
	{
		throw std::runtime_error("Passphrase cannot be specified twice.");
	}
	_passphrase = args.Argument();
	DEBUG("#SetPassphrase(%s)\n", _passphrase.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetKey(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-key: Value is missing.");
	}
	else if (_key)
	{
		throw std::runtime_error("Key cannot be specified twice.");
	}
	_key = ByteString::ParseHex(args.Argument());
	DEBUG("#SetKey(%s)\n", String::Hex(_key).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetIV(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-iv: Value is missing.");
	}
	else if (_iv)
	{
		throw std::runtime_error("IV cannot be specified twice.");
	}
	_iv = ByteString::ParseHex(args.Argument());
	DEBUG("#SetIV(%s)\n", String::Hex(_iv).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetNonce(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-nonce: Value is missing.");
	}
	else if (_nonce)
	{
		throw std::runtime_error("Nonce cannot be specified twice.");
	}
	_nonce = ByteString::ParseHex(args.Argument());
	DEBUG("#SetNonce(%s)\n", String::Hex(_nonce).Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetAdditionalAuthenticatedData(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-aad: Value is missing.");
	}
	else if (_aad)
	{
		throw std::runtime_error("AAD cannot be specified twice.");
	}
	_aad = args.Argument();
	DEBUG("#SetAdditionalAuthenticatedData(%s)\n", _aad.Ptr());
	return true;
}


bool MyCryptographyUtilityApplication::SetNonceLength(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-noncelength: Value is missing.");
	}
	else if (_nonceLength > 0)
	{
		throw std::runtime_error("Nonce length cannot be specified twice.");
	}
	char* stopped = nullptr;
	_nonceLength = strtoul(args.Argument(), &stopped, 10);
	if (args.Argument() == const_cast<const char*>(stopped) || *stopped || _nonceLength <= 0)
	{
		throw std::runtime_error("-noncelength: Value is invalid.");
	}
	DEBUG("#SetNonceLength(%d)\n", _nonceLength);
	return true;
}


bool MyCryptographyUtilityApplication::SetTagLength(CommandLine& args)
{
	if (!args.Next())
	{
		throw std::runtime_error("-taglength: Value is missing.");
	}
	else if (_tagLength > 0)
	{
		throw std::runtime_error("Tag length cannot be specified twice.");
	}
	char* stopped = nullptr;
	_tagLength = strtoul(args.Argument(), &stopped, 10);
	if (args.Argument() == const_cast<const char*>(stopped) || *stopped || _tagLength <= 0)
	{
		throw std::runtime_error("-taglength: Value is invalid.");
	}
	DEBUG("#SetTagLength(%d)\n", _tagLength);
	return true;
}


bool MyCryptographyUtilityApplication::Help(CommandLine& args)
{
	return false;
}


void MyCryptographyUtilityApplication::Run()
{
	if (_cipherMode == CipherMode::CIPHER_UNSPECIFIED && _digestMode == DigestMode::DIGEST_UNSPECIFIED)
	{
		throw std::runtime_error("Neither cipher nor digest is not specified. Specify either cipher or digest.");
	}
	else if (_cipherMode != CipherMode::CIPHER_UNSPECIFIED && _digestMode != DigestMode::DIGEST_UNSPECIFIED)
	{
		throw std::runtime_error("Both cipher and digest are specified. Specify either cipher or digest.");
	}
	switch (_operationMode)
	{
	case OperationMode::ENCRYPTION:
	case OperationMode::DECRYPTION:
		_console = IsStandardOutputMode() ? stderr : stdout;
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
		throw std::runtime_error("Operation is not specified. Specify either -encrypt or -decrypt.");
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
	if (!_inputPath)
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	if (!_outputPath)
	{
		throw std::runtime_error("Output file path is not specified.");
	}

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
	if (!_inputPath)
	{
		throw std::runtime_error("Input file path is not specified.");
	}
	if (!_outputPath)
	{
		throw std::runtime_error("Output file path is not specified.");
	}

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
		throw std::runtime_error("Neither key nor passphrase is specified. Specify either key or passphrase.");
	}
	else if (_key && _passphrase)
	{
		throw std::runtime_error("Both key and passphrase are specified. Specify either key or passphrase.");
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
	if (cipher->GetNonceLength())
	{
		if (_nonceLength)
		{
			cipher->SetNonceLength(_nonceLength);
		}
		if (!_nonce)
		{
			if (generateIfNotSpecified)
			{
				ComputeNonce(cipher);
			}
		}
		else if (static_cast<size_t>(cipher->GetNonceLength()) != _nonce.Length())
		{
			throw std::runtime_error(String::Format("Nonce is not valid in length. Expected=%d Actual=%zu", cipher->GetNonceLength(), _nonce.Length()));
		}
		if (_iv)
		{
			throw std::runtime_error("IV cannot be specified for the target cipher.");
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
	else if (cipher->GetIvLength())
	{
		if (!_iv)
		{
			if (generateIfNotSpecified)
			{
				ComputeIV(cipher);
			}
		}
		else if (static_cast<size_t>(cipher->GetIvLength()) != _iv.Length())
		{
			throw std::runtime_error(String::Format("IV is not valid in length. Expected=%d Actual=%zu", cipher->GetIvLength(), _iv.Length()));
		}
	}
	else if (_iv)
	{
		throw std::runtime_error("IV cannot be specified for the target cipher.");
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
	String hex = String::Lowercase(String::Hex(result));
	fprintf(stdout, "%s\n", hex.Ptr());
}
