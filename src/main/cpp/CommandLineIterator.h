// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_COMMANDLINEITERATOR_H
#define MYCRYPTO_COMMANDLINEITERATOR_H

namespace hnrt
{
	class CommandLineIterator
	{
	public:

		CommandLineIterator(int argc, char* argv[]);
		CommandLineIterator(const CommandLineIterator&) = delete;
		~CommandLineIterator() = default;
		bool HasNext() const;
		const char* Next();

	private:

		int _argc;
		char** _argv;
		int _index;
	};

	inline CommandLineIterator::CommandLineIterator(int argc, char* argv[])
		: _argc(argc)
		, _argv(argv)
		, _index(1)
	{
	}

	inline bool CommandLineIterator::HasNext() const
	{
		return _index < _argc;
	}

	inline const char* CommandLineIterator::Next()
	{
		return _index < _argc ? _argv[_index++] : nullptr;
	}
}

#endif //!MYCRYPTO_COMMANDLINEITERATOR_H
