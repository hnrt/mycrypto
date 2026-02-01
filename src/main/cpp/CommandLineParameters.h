// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_COMMANDLINEPARAMETERS_H
#define MYCRYPTO_COMMANDLINEPARAMETERS_H

#include "StringEx.h"
#include "Parameter.h"
#include <map>
#include <vector>

namespace hnrt
{
	class MyCryptographyUtilityApplication;

	class CommandLineParameters
	{
	public:

		CommandLineParameters();
		CommandLineParameters(const CommandLineParameters&) = delete;
		~CommandLineParameters();
		CommandLineParameters& Add(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLine& args));
		CommandLineParameters& AddAlias(const char* alias, const char* key);
		bool Process(int argc, char* argv[], MyCryptographyUtilityApplication& app);
		String ToString() const;

	private:

		std::vector<Parameter> _parameters;
		std::map<String, Parameter> _mappings;
		std::map<String, String> _aliases;
	};
}

#endif //!MYCRYPTO_COMMANDLINEPARAMETERS_H
