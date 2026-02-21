// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_COMMANDLINEOPTION_H
#define MYCRYPTO_COMMANDLINEOPTION_H

#include "StringEx.h"
#include "CommandLineIterator.h"

namespace hnrt
{
	class MyCryptographyUtilityApplication;

	class CommandLineOption
	{
	public:

		CommandLineOption();
		CommandLineOption(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* _function)(CommandLineIterator& iterator));
		CommandLineOption(const CommandLineOption& src);
		~CommandLineOption();
		const String& Key() const;
		const String& Operand() const;
		const String& Description() const;
		bool Apply(MyCryptographyUtilityApplication& app, CommandLineIterator& iterator);

	private:

		String _key;
		String _operand;
		String _description;
		bool (MyCryptographyUtilityApplication::* _function)(CommandLineIterator& iterator);
	};

	inline CommandLineOption::CommandLineOption()
		: _key()
		, _operand()
		, _description()
		, _function(nullptr)
	{
	}

	inline CommandLineOption::CommandLineOption(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLineIterator& iterator))
		: _key(key)
		, _operand(operand)
		, _description(description)
		, _function(function)
	{
	}

	inline CommandLineOption::CommandLineOption(const CommandLineOption& src)
		: _key(src._key)
		, _operand(src._operand)
		, _description(src._description)
		, _function(src._function)
	{
	}
	
	inline CommandLineOption::~CommandLineOption()
	{
	}

	inline const String& CommandLineOption::Key() const
	{
		return _key;
	}

	inline const String& CommandLineOption::Operand() const
	{
		return _operand;
	}

	inline const String& CommandLineOption::Description() const
	{
		return _description;
	}

	inline bool CommandLineOption::Apply(MyCryptographyUtilityApplication& app, CommandLineIterator& iterator)
	{
		return (app.*_function)(iterator);
	}
}

#endif //!MYCRYPTO_COMMANDLINEOPTION_H
