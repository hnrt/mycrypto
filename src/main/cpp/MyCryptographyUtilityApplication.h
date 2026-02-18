// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTOGRAPHYUTILITYAPPLICATION_H
#define MYCRYPTOGRAPHYUTILITYAPPLICATION_H

#include "OperationMode.h"
#include "CipherMode.h"
#include "DigestMode.h"
#include "CipherPtr.h"
#include "StringEx.h"
#include "ByteString.h"
#include "CommandLine.h"
#include "File.h"
#include <stdio.h>

namespace hnrt
{
	class MyCryptographyUtilityApplication
	{
	public:

		MyCryptographyUtilityApplication();
		MyCryptographyUtilityApplication(const MyCryptographyUtilityApplication&) = delete;
		~MyCryptographyUtilityApplication();
		bool SetAes128Ecb(CommandLine& args);
		bool SetAes192Ecb(CommandLine& args);
		bool SetAes256Ecb(CommandLine& args);
		bool SetAes128Cbc(CommandLine& args);
		bool SetAes192Cbc(CommandLine& args);
		bool SetAes256Cbc(CommandLine& args);
		bool SetAes128Cfb(CommandLine& args);
		bool SetAes192Cfb(CommandLine& args);
		bool SetAes256Cfb(CommandLine& args);
		bool SetAes128Cfb8(CommandLine& args);
		bool SetAes192Cfb8(CommandLine& args);
		bool SetAes256Cfb8(CommandLine& args);
		bool SetAes128Ofb(CommandLine& args);
		bool SetAes192Ofb(CommandLine& args);
		bool SetAes256Ofb(CommandLine& args);
		bool SetAes128Ctr(CommandLine& args);
		bool SetAes192Ctr(CommandLine& args);
		bool SetAes256Ctr(CommandLine& args);
		bool SetAes128Ccm(CommandLine& args);
		bool SetAes192Ccm(CommandLine& args);
		bool SetAes256Ccm(CommandLine& args);
		bool SetAes128Gcm(CommandLine& args);
		bool SetAes192Gcm(CommandLine& args);
		bool SetAes256Gcm(CommandLine& args);
		bool SetMD5(CommandLine& args);
		bool SetSHA1(CommandLine& args);
		bool SetSHA256(CommandLine& args);
		bool SetSHA384(CommandLine& args);
		bool SetSHA512(CommandLine& args);
		bool SetEncryptionMode(CommandLine& args);
		bool SetDecryptionMode(CommandLine& args);
		bool SetInputPath(CommandLine& args);
		bool SetOutputPath(CommandLine& args);
		bool SetKey(CommandLine& args);
		bool SetIV(CommandLine& args);
		bool SetNonce(CommandLine& args);
		bool SetPassphrase(CommandLine& args);
		bool SetAdditionalAuthenticatedData(CommandLine& args);
		bool SetNonceLength(CommandLine& args);
		bool SetTagLength(CommandLine& args);
		bool Help(CommandLine& args);
		void Run();
		void Rollback();

	private:

		void SetCipherMode(CipherMode mode);
		void SetDigestMode(DigestMode mode);
		bool IsStandardInputMode() const;
		bool IsStandardOutputMode() const;
		void Encrypt();
		void Decrypt();
		void VerifyKey(const CipherPtr& cipher);
		void VerifyIV(CipherPtr& cipher, bool generateIfNotSpecified = false);
		void VerifyNonce(CipherPtr& cipher, bool generateIfNotSpecified = false);
		void ReadOnceFromStandardInput(File& inputStream);
		void ComputeKey(const CipherPtr& cipher);
		void ComputeIV(const CipherPtr& cipher);
		void ComputeNonce(const CipherPtr& cipher);
		void PrintCipherResult(const ByteString& tag, const File& inputStream, const File& outputStream);
		void ComputeDigest();

		OperationMode _operationMode;
		CipherMode _cipherMode;
		DigestMode _digestMode;
		String _inputPath;
		String _outputPath;
		String _temporaryPath;
		String _passphrase;
		String _aad;
		ByteString _key;
		ByteString _iv;
		ByteString _nonce;
		int _nonceLength;
		int _tagLength;
		FILE* _console;
	};
}

#endif //!MYCRYPTOGRAPHYUTILITYAPPLICATION_H
