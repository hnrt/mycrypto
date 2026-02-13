// Copyright (C) 2026 Hideaki Narita


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <stdexcept>
#include "MyCryptographyUtilityApplication.h"
#include "CommandLineParameters.h"
#include "File.h"


using namespace hnrt;


static void Help(const char* arg0, const CommandLineParameters& parameters)
{
	arg0 = strchr(arg0, DIRECTORY_SEPARATOR_CHAR) ? strrchr(arg0, DIRECTORY_SEPARATOR_CHAR) + 1 : arg0;
	fprintf(stdout, "Syntax:\n");
	fprintf(stdout, "  %s parameters\n", arg0);
	fprintf(stdout, "%s", parameters.ToString().Ptr());
}


int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "");

	MyCryptographyUtilityApplication app;
	CommandLineParameters parameters;

	try
	{
		parameters
			.Add("aes-128-ecb", NULL, "cipher: AES [Electronic CodeBook] key=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes128Ecb)
			.Add("aes-192-ecb", NULL, "cipher: AES [Electronic CodeBook] key=24 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes192Ecb)
			.Add("aes-256-ecb", NULL, "cipher: AES [Electronic CodeBook] key=32 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes256Ecb)
			.Add("aes-128-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=16 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes128Cbc)
			.Add("aes-192-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=24 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes192Cbc)
			.Add("aes-256-cbc", NULL, "cipher: AES [Cipher Block Chaining] key=32 iv=16 padding=PKCS5", &MyCryptographyUtilityApplication::SetAes256Cbc)
			.Add("aes-128-cfb1", NULL, "cipher: AES [1-bit Cipher Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Cfb1)
			.Add("aes-192-cfb1", NULL, "cipher: AES [1-bit Cipher Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Cfb1)
			.Add("aes-256-cfb1", NULL, "cipher: AES [1-bit Cipher Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Cfb1)
			.Add("aes-128-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Cfb8)
			.Add("aes-192-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Cfb8)
			.Add("aes-256-cfb8", NULL, "cipher: AES [8-bit Cipher Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Cfb8)
			.Add("aes-128-cfb128", NULL, "cipher: AES [128-bit Cipher Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Cfb128)
			.Add("aes-192-cfb128", NULL, "cipher: AES [128-bit Cipher Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Cfb128)
			.Add("aes-256-cfb128", NULL, "cipher: AES [128-bit Cipher Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Cfb128)
			.Add("aes-128-ofb", NULL, "cipher: AES [8-bit Output Feedback Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Ofb)
			.Add("aes-192-ofb", NULL, "cipher: AES [8-bit Output Feedback Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Ofb)
			.Add("aes-256-ofb", NULL, "cipher: AES [8-bit Output Feedback Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Ofb)
			.Add("aes-128-ctr", NULL, "cipher: AES [Counter Mode] key=16 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes128Ctr)
			.Add("aes-192-ctr", NULL, "cipher: AES [Counter Mode] key=24 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes192Ctr)
			.Add("aes-256-ctr", NULL, "cipher: AES [Counter Mode] key=32 iv=16 padding=none", &MyCryptographyUtilityApplication::SetAes256Ctr)
			.Add("aes-128-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=16 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes128Ccm)
			.Add("aes-192-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=24 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes192Ccm)
			.Add("aes-256-ccm", NULL, "cipher: AES [Counter with CBC-MAC] key=32 nonce=7 tag=12", &MyCryptographyUtilityApplication::SetAes256Ccm)
			.Add("aes-128-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=16 nonce=12 tag=16", &MyCryptographyUtilityApplication::SetAes128Gcm)
			.Add("aes-192-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=24 nonce=12 tag=16", &MyCryptographyUtilityApplication::SetAes192Gcm)
			.Add("aes-256-gcm", NULL, "cipher: AES [Galois/Counter Mode] key=32 nonce=12 tag=16 [default]", &MyCryptographyUtilityApplication::SetAes256Gcm)
			.Add("md5", NULL, "digest: MD5 (16 bytes long)", &MyCryptographyUtilityApplication::SetMD5)
			.Add("sha1", NULL, "digest: SHA1 (20 bytes long)", &MyCryptographyUtilityApplication::SetSHA1)
			.Add("sha256", NULL, "digest: SHA256 (32 bytes long)", &MyCryptographyUtilityApplication::SetSHA256)
			.Add("sha384", NULL, "digest: SHA384 (48 bytes long)", &MyCryptographyUtilityApplication::SetSHA384)
			.Add("sha512", NULL, "digest: SHA512 (64 bytes long)", &MyCryptographyUtilityApplication::SetSHA512)
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
			.Add("-help", NULL, "prints this message", &MyCryptographyUtilityApplication::Help)
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
		if (argc == 1)
		{
			Help(argv[0], parameters);
		}
		else if (parameters.Process(argc, argv, app))
		{
			app.Run();
		}
		else
		{
			Help(argv[0], parameters);
		}
		return EXIT_SUCCESS;
	}
	catch (const std::exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		app.Rollback();
		return EXIT_FAILURE;
	}
}
