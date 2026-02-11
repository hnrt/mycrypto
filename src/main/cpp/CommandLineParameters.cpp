// Copyright (C) 2026 Hideaki Narita


#include "CommandLineParameters.h"
#include "StringEx.h"
#include "Parameter.h"
#include "CommandLine.h"
#include "MyCryptographyUtilityApplication.h"
#include <string.h>
#include <map>
#include <stdexcept>


using namespace hnrt;


CommandLineParameters::CommandLineParameters()
	: _parameters()
	, _mappings()
	, _aliases()
{
}


CommandLineParameters::~CommandLineParameters()
{
}


CommandLineParameters& CommandLineParameters::Add(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLine& args))
{
	Parameter parameter(key, operand, description, function);
	_parameters.push_back(parameter);
	_mappings.insert(std::pair<String, Parameter>(String(key), parameter));
	return *this;
}


CommandLineParameters& CommandLineParameters::AddAlias(const char* alias, const char* key)
{
	String k(key);
	std::map<String, Parameter>::iterator iter = _mappings.find(k);
	if (iter == _mappings.end())
	{
		throw std::runtime_error(String::Format("%s: Not yet registered.", key).Ptr());
	}
	_aliases.insert(std::pair<String, String>(String(alias), iter == _mappings.end() ? k : iter->first));
	return *this;
}


bool CommandLineParameters::Process(int argc, char* argv[], MyCryptographyUtilityApplication& app)
{
	CommandLine args(argc, argv);
	while (args.Next())
	{
		String key = args.Argument();
		std::map <String, String>::iterator iterA = _aliases.find(key);
		if (iterA != _aliases.end())
		{
			key = iterA->second;
		}
		std::map<String, Parameter>::iterator iter = _mappings.find(key);
		if (iter == _mappings.end())
		{
			throw std::runtime_error(String::Format("Bad command line syntax: %s", key.Ptr()).Ptr());
		}
		if (!iter->second.Invoke(app, args))
		{
			return false;
		}
	}
	return true;
}


String CommandLineParameters::ToString() const
{
	size_t width1 = 0;
	for (std::vector<Parameter>::const_iterator iter = _parameters.cbegin(); iter != _parameters.cend(); iter++)
	{
		const char* key = iter->Key();
		const char* operand = iter->Operand();
		size_t n = strlen(key) + (operand ? 1 + strlen(operand) : 0);
		if (width1 < n)
		{
			width1 = n;
		}
	}
	String s("Parameters:\n");
	for (std::vector<Parameter>::const_iterator iter = _parameters.cbegin(); iter != _parameters.cend(); iter++)
	{
		const char* key = iter->Key();
		const char* operand = iter->Operand();
		const char* description = iter->Description();
		const char* descriptionEnd = strchr(description, '\n');
		size_t width2 = descriptionEnd ? (descriptionEnd - description) : strlen(description);
		s += String::Format("  %-*s  %.*s\n",
			static_cast<int>(width1), String::Format(operand ? "%s %s" : "%s", key, operand).Ptr(),
			static_cast<int>(width2), description);
		while (descriptionEnd)
		{
			description = descriptionEnd + 1;
			descriptionEnd = strchr(description, '\n');
			width2 = descriptionEnd ? (descriptionEnd - description) : strlen(description);
			s += String::Format("  %-*s  %.*s\n",
				static_cast<int>(width1), " ",
				static_cast<int>(width2), description);
		}
	}
	s += "Aliases:\n";
	for (std::vector<Parameter>::const_iterator iter = _parameters.cbegin(); iter != _parameters.cend(); iter++)
	{
		const char* key = iter->Key();
		for (std::map<String, String>::const_iterator iterA = _aliases.cbegin(); iterA != _aliases.cend(); iterA++)
		{
			if (!strcmp(iterA->second, key))
			{
				s += String::Format("  %-*s  is the same as %s\n", static_cast<int>(width1), iterA->first.Ptr(), iterA->second.Ptr());
			}
		}
	}
	return s;
}
