// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_COMMANDLINEOPTIONSET_H
#define MYCRYPTO_COMMANDLINEOPTIONSET_H

#include "StringEx.h"
#include "CommandLineOption.h"
#include "CommandLineIterator.h"
#include <map>
#include <vector>

namespace hnrt
{
	class MyCryptographyUtilityApplication;

	class CommandLineOptionSet
	{
	public:

		CommandLineOptionSet(const char* name);
		CommandLineOptionSet(const CommandLineOptionSet&) = delete;
		~CommandLineOptionSet() = default;
		CommandLineOptionSet& Add(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLineIterator& iterator));
		CommandLineOptionSet& AddAlias(const char* alias, const char* key);
		bool Process(MyCryptographyUtilityApplication& app, int argc, char* argv[]);
		bool Process(MyCryptographyUtilityApplication& app, CommandLineIterator& iterator);
		String ToString() const;

		static void AlignFormat(CommandLineOptionSet* pOptionSet, ...);

	private:

		int MeasureKeyOperandLength(int separatorLength) const;
		void SetFormat(int keyOperandLength);

		String _name;
		std::vector<CommandLineOption> _options;
		std::map<String, CommandLineOption> _omap;
		std::vector<String> _aliases;
		std::map<String, String> _amap;
		String _format;
		String _wrappingLine;
	};
}

#endif //!MYCRYPTO_COMMANDLINEOPTIONSET_H
