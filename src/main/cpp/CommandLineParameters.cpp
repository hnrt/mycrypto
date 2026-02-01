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
			throw std::runtime_error(String::Format("Bad command line syntax: %s", key).Ptr());
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
	String s("Parameters:\n");
	size_t m = 0;
	std::vector<Parameter>::const_iterator iter = _parameters.cbegin();
	while (iter != _parameters.cend())
	{
		const char* key = iter->Key();
		const char* operand = iter->Operand();
		size_t n = strlen(key) + (operand ? 1 + strlen(operand) : 0);
		if (m < n)
		{
			m = n;
		}
		iter++;
	}
	iter = _parameters.cbegin();
	while (iter != _parameters.cend())
	{
		const char* key = iter->Key();
		const char* operand = iter->Operand();
		const char* description = iter->Description();
		s = String::Format("%s  %-*s  %s\n", s.Ptr(),
			static_cast<int>(m), String::Format(operand ? "%s %s" : "%s", key, operand).Ptr(),
			description);
		iter++;
	}
	return s;
}
