// Copyright (C) 2026 Hideaki Narita


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <stdexcept>
#include "MyCryptographyUtilityApplication.h"


using namespace hnrt;


int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "");

	MyCryptographyUtilityApplication app;

	try
	{
		if (argc == 1)
		{
			app.Help(argv[0]);
		}
		else if (app.Parse(argc, argv))
		{
			app.Run();
		}
		else
		{
			app.Help(argv[0]);
		}
		return EXIT_SUCCESS;
	}
	catch (const std::exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		app.Rollback();
		return EXIT_FAILURE;
	}
}
