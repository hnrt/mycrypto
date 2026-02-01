// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_PARAMETER_H
#define MYCRYPTO_PARAMETER_H

#include "StringEx.h"
#include "CommandLine.h"
#include "MyCryptographyUtilityApplication.h"

namespace hnrt
{
	class Parameter
	{
	public:

		Parameter();
		Parameter(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLine& args));
		Parameter(const Parameter& src);
		~Parameter() = default;
		Parameter& operator = (const Parameter& src);
		const char* Key() const;
		const char* Operand() const;
		const char* Description() const;
		bool Invoke(MyCryptographyUtilityApplication& app, CommandLine& args);

	protected:

		String _key;
		String _operand;
		String _description;
		bool (MyCryptographyUtilityApplication::* _function)(CommandLine& args);
	};
}

#endif //!MYCRYPTO_PARAMETER_H
