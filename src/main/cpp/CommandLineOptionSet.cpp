// Copyright (C) 2026 Hideaki Narita


#include "CommandLineOptionSet.h"
#include "StringEx.h"
#include "CommandLineOption.h"
#include "CommandLineIterator.h"
#include "MyCryptographyUtilityApplication.h"
#include <stdarg.h>
#include <string.h>
#include <map>
#include <stdexcept>


using namespace hnrt;


CommandLineOptionSet::CommandLineOptionSet(const char* name)
	: _name(name)
	, _options()
	, _omap()
	, _aliases()
	, _amap()
{
}


CommandLineOptionSet& CommandLineOptionSet::Add(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLineIterator& iterator))
{
	CommandLineOption option(key, operand, description, function);
	_options.push_back(option);
	_omap.insert(std::pair<String, CommandLineOption>(option.Key(), option));
	return *this;
}


CommandLineOptionSet& CommandLineOptionSet::AddAlias(const char* alias, const char* key)
{
	std::map<String, CommandLineOption>::const_iterator mIterator = _omap.find(String(key));
	if (mIterator == _omap.cend())
	{
		throw std::runtime_error(String::Format("%s ==> %s is not registered!", alias, key));
	}
	String a(alias);
	_aliases.push_back(a);
	_amap.insert(std::pair<String, String>(a, mIterator->first));
	return *this;
}


bool CommandLineOptionSet::Process(MyCryptographyUtilityApplication& app, int argc, char* argv[])
{
	CommandLineIterator iterator(argc, argv);
	return Process(app, iterator);
}


bool CommandLineOptionSet::Process(MyCryptographyUtilityApplication& app, CommandLineIterator& iterator)
{
	while (iterator.HasNext())
	{
		String key(iterator.Next());
		std::map<String, CommandLineOption>::iterator mIterator = _omap.find(key);
		if (mIterator == _omap.end())
		{
			std::map <String, String>::iterator aIterator = _amap.find(key);
			if (aIterator == _amap.end())
			{
				throw std::runtime_error(String::Format("Bad command line syntax: %s", key.Ptr()));
			}
			mIterator = _omap.find(aIterator->second);
		}
		if (!mIterator->second.Apply(app, iterator))
		{
			return false;
		}
	}
	return true;
}


String CommandLineOptionSet::ToString() const
{
	String s(_name);
	s += String(":\n");
	for (std::vector<CommandLineOption>::const_iterator iterator = _options.cbegin(); iterator != _options.cend(); iterator++)
	{
		if (iterator->Description())
		{
			const char* key = iterator->Key();
			const char* operand = iterator->Operand();
			String description("");
			const char* start = iterator->Description();
			const char* stop = strchr(start, '\n');
			while (stop != nullptr)
			{
				description += String(start, stop - start);
				description += _wrappingLine;
				start = stop + 1;
				stop = strchr(start, '\n');
			}
			description += String(start);
			s += String::Format(_format.Ptr(), String::Format(operand ? "%s %s" : "%s", key, operand).Ptr(), description.Ptr());
		}
	}
	for (std::vector<String>::const_iterator iterator = _aliases.cbegin(); iterator != _aliases.cend(); iterator++)
	{
		String key(*iterator);
		std::map <String, String>::const_iterator aIterator = _amap.find(key);
		std::map<String, CommandLineOption>::const_iterator mIterator = _omap.find(aIterator->second);
		if (mIterator->second.Description())
		{
			s += String::Format(_format.Ptr(), key.Ptr(), String::Format("is an alias of %s", aIterator->second.Ptr()).Ptr());
		}
	}
	return s;
}


int CommandLineOptionSet::MeasureKeyOperandLength(int separatorLength) const
{
	int length = 0;
	for (std::vector<CommandLineOption>::const_iterator iterator = _options.cbegin(); iterator != _options.cend(); iterator++)
	{
		if (iterator->Description())
		{
			int n1 = static_cast<int>(iterator->Key().Length());
			int n2 = iterator->Operand() ? separatorLength + static_cast<int>(iterator->Operand().Length()) : 0;
			int n = n1 + n2;
			if (length < n)
			{
				length = n;
			}
		}
	}
	for (std::vector<String>::const_iterator iterator = _aliases.cbegin(); iterator != _aliases.cend(); iterator++)
	{
		String key(*iterator);
		std::map <String, String>::const_iterator aIterator = _amap.find(key);
		std::map<String, CommandLineOption>::const_iterator mIterator = _omap.find(aIterator->second);
		if (mIterator->second.Description())
		{
			int n = static_cast<int>(key.Length());
			if (length < n)
			{
				length = n;
			}
		}
	}
	return length;
}


void CommandLineOptionSet::SetFormat(int keyOperandLength)
{
	_format = String::Format("  %%-%ds  %%s\n", keyOperandLength);
	_wrappingLine = String::Format("\n%-*s", keyOperandLength + 4, " ");
}


void CommandLineOptionSet::AlignFormat(CommandLineOptionSet* pOptionSet, ...)
{
	int length = 0;
	va_list argList;
	va_start(argList, pOptionSet);
	for (CommandLineOptionSet* pNext = pOptionSet; pNext != nullptr; pNext = va_arg(argList, CommandLineOptionSet*))
	{
		int n = pNext->MeasureKeyOperandLength(1);
		if (length < n)
		{
			length = n;
		}
	}
	va_end(argList);
	va_start(argList, pOptionSet);
	for (CommandLineOptionSet* pNext = pOptionSet; pNext != nullptr; pNext = va_arg(argList, CommandLineOptionSet*))
	{
		pNext->SetFormat(length);
	}
	va_end(argList);
}
