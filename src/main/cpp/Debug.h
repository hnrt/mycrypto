// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_DEBUG_H
#define MYCRYPTO_DEBUG_H

#include <stdio.h>

#ifdef _DEBUG
#define DEBUG(fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#else //_DEBUG
#define DEBUG(fmt,...) (void)0
#endif //_DEBUG

#endif //!MYCRYPTO_DEBUG_H
