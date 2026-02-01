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
			.Add("aes-256-gcm", NULL, "Sets cipher mode to AES/GCM key=32 iv=12 tag=16.", &MyCryptographyUtilityApplication::SetAes256Gcm)
			.Add("md5", NULL, "Sets digest mode to MD5 (16 bytes long).", &MyCryptographyUtilityApplication::SetMD5)
			.Add("sha1", NULL, "Sets digest mode to SHA1 (20 bytes long).", &MyCryptographyUtilityApplication::SetSHA1)
			.Add("sha256", NULL, "Sets digest mode to SHA256 (32 bytes long).", &MyCryptographyUtilityApplication::SetSHA256)
			.Add("sha384", NULL, "Sets digest mode to SHA384 (48 bytes long).", &MyCryptographyUtilityApplication::SetSHA384)
			.Add("sha512", NULL, "Sets digest mode to SHA512 (64 bytes long). ", &MyCryptographyUtilityApplication::SetSHA512)
			.Add("-encrypt", NULL, "Sets operation mode to encryption.", &MyCryptographyUtilityApplication::SetEncryptionMode)
			.Add("-decrypt", NULL, "Sets operation mode to decryption.", &MyCryptographyUtilityApplication::SetDecryptionMode)
			.Add("-input", "PATH", "Specifies input file path.", &MyCryptographyUtilityApplication::SetInputPath)
			.Add("-output", "PATH", "Specifies output file path.", &MyCryptographyUtilityApplication::SetOutputPath)
			.Add("-passphrase", "TEXT", "Specifies passphrase to generate key.", &MyCryptographyUtilityApplication::SetPassphrase)
			.Add("-key", "HEX", "Specifies private key.", &MyCryptographyUtilityApplication::SetKey)
			.Add("-iv", "HEX", "Specifies initial vector.", &MyCryptographyUtilityApplication::SetIv)
			.Add("-aad", "TEXT", "Specifies additional authenticated data.", &MyCryptographyUtilityApplication::SetAdditionalAuthenticatedData)
			.AddAlias("-e", "-encrypt")
			.AddAlias("-enc", "-encrypt")
			.AddAlias("-d", "-decrypt")
			.AddAlias("-dec", "-decrypt")
			.AddAlias("-i", "-input")
			.AddAlias("-in", "-input")
			.AddAlias("-o", "-output")
			.AddAlias("-out", "-output")
			.AddAlias("-p", "-passphrase")
			.AddAlias("-pass", "-passphrase")
			.AddAlias("-password", "-passphrase");
		if (argc == 1)
		{
			Help(argv[0], parameters);
		}
		else if (parameters.Process(argc, argv, app))
		{
			app.Run();
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
