// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTOGRAPHYUTILITYAPPLICATION_H
#define MYCRYPTOGRAPHYUTILITYAPPLICATION_H

#include "OperationMode.h"
#include "CipherMode.h"
#include "DigestMode.h"
#include "CipherPtr.h"
#include "StringEx.h"
#include "ByteString.h"
#include "CommandLineIterator.h"
#include "CommandLineOptionSet.h"
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
		bool SetAes128Ecb(CommandLineIterator& iterator);
		bool SetAes192Ecb(CommandLineIterator& iterator);
		bool SetAes256Ecb(CommandLineIterator& iterator);
		bool SetAes128Cbc(CommandLineIterator& iterator);
		bool SetAes192Cbc(CommandLineIterator& iterator);
		bool SetAes256Cbc(CommandLineIterator& iterator);
		bool SetAes128Cfb(CommandLineIterator& iterator);
		bool SetAes192Cfb(CommandLineIterator& iterator);
		bool SetAes256Cfb(CommandLineIterator& iterator);
		bool SetAes128Cfb8(CommandLineIterator& iterator);
		bool SetAes192Cfb8(CommandLineIterator& iterator);
		bool SetAes256Cfb8(CommandLineIterator& iterator);
		bool SetAes128Ofb(CommandLineIterator& iterator);
		bool SetAes192Ofb(CommandLineIterator& iterator);
		bool SetAes256Ofb(CommandLineIterator& iterator);
		bool SetAes128Ctr(CommandLineIterator& iterator);
		bool SetAes192Ctr(CommandLineIterator& iterator);
		bool SetAes256Ctr(CommandLineIterator& iterator);
		bool SetAes128Ccm(CommandLineIterator& iterator);
		bool SetAes192Ccm(CommandLineIterator& iterator);
		bool SetAes256Ccm(CommandLineIterator& iterator);
		bool SetAes128Gcm(CommandLineIterator& iterator);
		bool SetAes192Gcm(CommandLineIterator& iterator);
		bool SetAes256Gcm(CommandLineIterator& iterator);
		bool SetMD5(CommandLineIterator& iterator);
		bool SetSHA1(CommandLineIterator& iterator);
		bool SetSHA256(CommandLineIterator& iterator);
		bool SetSHA384(CommandLineIterator& iterator);
		bool SetSHA512(CommandLineIterator& iterator);
		bool SetEncryptionMode(CommandLineIterator& iterator);
		bool SetDecryptionMode(CommandLineIterator& iterator);
		bool SetInputPath(CommandLineIterator& iterator);
		bool SetOutputPath(CommandLineIterator& iterator);
		bool SetKey(CommandLineIterator& iterator);
		bool SetIV(CommandLineIterator& iterator);
		bool SetNonce(CommandLineIterator& iterator);
		bool SetPassphrase(CommandLineIterator& iterator);
		bool SetAdditionalAuthenticatedData(CommandLineIterator& iterator);
		bool SetNonceLength(CommandLineIterator& iterator);
		bool SetTagLength(CommandLineIterator& iterator);
		bool Help(CommandLineIterator& iterator);
		bool Parse(int argc, char* argv[]);
		void Run();
		void Rollback();
		void Help(const char* arg0);

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
		CommandLineOptionSet _optionSet;
		CommandLineOptionSet _cipherOptionSet;
		CommandLineOptionSet _digestOptionSet;
	};
}

#endif //!MYCRYPTOGRAPHYUTILITYAPPLICATION_H
