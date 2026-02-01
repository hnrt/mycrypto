// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_HEAP_H
#define MYCRYPTO_HEAP_H

#include <stddef.h>

namespace hnrt
{
	void* Allocate(size_t size);
	void* Reallocate(void* ptr, size_t size);
}

#endif //!MYCRYPTO_HEAP_H
