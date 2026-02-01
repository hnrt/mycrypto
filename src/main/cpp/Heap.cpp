// Copyright (C) 2026 Hideaki Narita


#include "Heap.h"
#include <stdlib.h>
#include <stdexcept>


using namespace hnrt;


void* hnrt::Allocate(size_t size)
{
	void* ptr = malloc(size);
	if (!ptr)
	{
		throw std::bad_alloc();
	}
	return ptr;
}


void* hnrt::Reallocate(void* ptr, size_t size)
{
	void* ptr2 = realloc(ptr, size);
	if (!ptr2)
	{
		throw std::bad_alloc();
	}
	return ptr2;
}
