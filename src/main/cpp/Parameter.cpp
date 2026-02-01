// Copyright (C) 2026 Hideaki Narita


#include "Parameter.h"
#include "StringEx.h"
#include "MyCryptographyUtilityApplication.h"
#include <stdexcept>


using namespace hnrt;


Parameter::Parameter()
	: _key()
	, _operand()
	, _description()
	, _function(NULL)
{
}


Parameter::Parameter(const char* key, const char* operand, const char* description, bool (MyCryptographyUtilityApplication::* function)(CommandLine& args))
	: _key(key)
	, _operand(operand)
	, _description(description)
	, _function(function)
{
}


Parameter::Parameter(const Parameter& src)
	: _key(src._key)
	, _operand(src._operand)
	, _description(src._description)
	, _function(src._function)
{
}


Parameter& Parameter::operator = (const Parameter& src)
{
	_key = src._key;
	_operand = src._operand;
	_description = src._description;
	_function = src._function;
	return *this;
}


const char* Parameter::Key() const
{
	return _key;
}


const char* Parameter::Operand() const
{
	return _operand;
}


const char* Parameter::Description() const
{
	return _description;
}


bool Parameter::Invoke(MyCryptographyUtilityApplication& app, CommandLine& args)
{
	return (app.*_function)(args);
}
