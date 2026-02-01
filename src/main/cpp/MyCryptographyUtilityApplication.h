// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTOGRAPHYUTILITYAPPLICATION_H
#define MYCRYPTOGRAPHYUTILITYAPPLICATION_H

#include "OperationMode.h"
#include "CipherMode.h"
#include "DigestMode.h"
#include "StringEx.h"
#include "ByteString.h"
#include "CommandLine.h"

namespace hnrt
{
	class MyCryptographyUtilityApplication
	{
	public:

		MyCryptographyUtilityApplication();
		MyCryptographyUtilityApplication(const MyCryptographyUtilityApplication&) = delete;
		~MyCryptographyUtilityApplication();
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
		bool SetIv(CommandLine& args);
		bool SetPassphrase(CommandLine& args);
		bool SetAdditionalAuthenticatedData(CommandLine& args);
		void Run();
		void Rollback();

	private:

		void SetDigestMode(DigestMode mode);
		void Encrypt();
		void Decrypt();
		void ComputeDigest();
		void ComputeKey();
		void ComputeIv();

		OperationMode _operationMode;
		CipherMode _cipherMode;
		DigestMode _digestMode;
		String _inputPath;
		String _outputPath;
		String _passphrase;
		String _aad;
		ByteString _key;
		ByteString _iv;
	};
}

#endif //!MYCRYPTOGRAPHYUTILITYAPPLICATION_H
