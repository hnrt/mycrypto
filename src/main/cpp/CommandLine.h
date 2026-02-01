// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_COMMANDLINE_H
#define MYCRYPTO_COMMANDLINE_H

namespace hnrt
{
	class CommandLine
	{
	public:

		CommandLine(int argc, char* argv[]);
		CommandLine(const CommandLine&) = delete;
		~CommandLine() = default;
		bool Next();
		const char* Argument() const;

	private:

		int _argc;
		char** _argv;
		int _index;
	};
}

#endif //!MYCRYPTO_COMMANDLINE_H
