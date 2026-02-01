// Copyright (C) 2026 Hideaki Narita


#include "CommandLine.h"


using namespace hnrt;


CommandLine::CommandLine(int argc, char* argv[])
	: _argc(argc)
	, _argv(argv)
	, _index(0)
{
}


bool CommandLine::Next()
{
	return ++_index < _argc;
}


const char* CommandLine::Argument() const
{
	return _argv[_index];
}
