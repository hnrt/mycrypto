// Copyright (C) 2026 Hideaki Narita


#include "DigestMode.h"


using namespace hnrt;


const char* hnrt::DigestModeText(DigestMode mode)
{
	switch (mode)
	{
	case DigestMode::MD5:
		return "MD5";
	case DigestMode::SHA1:
		return "SHA1";
	case DigestMode::SHA256:
		return "SHA256";
	case DigestMode::SHA384:
		return "SHA384";
	case DigestMode::SHA512:
		return "SHA512";
	default:
		return "?";
	}
}
