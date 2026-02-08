// Copyright (C) 2026 Hideaki Narita


#include "StringEx.h"
#include "Heap.h"
#include "ByteString.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdexcept>
#include <stdarg.h>
#include <ctype.h>


using namespace hnrt;


inline static void* AllocatedBlock(char* s)
{
	return &reinterpret_cast<size_t*>(s)[-2];
}


inline static size_t& ReferenceCount(char* s)
{
	return reinterpret_cast<size_t*>(s)[-2];
}


inline static size_t& StringLength(char* s)
{
	return reinterpret_cast<size_t*>(s)[-1];
}


char* String::Allocate(size_t len)
{
	size_t* h = reinterpret_cast<size_t*>(hnrt::Allocate(sizeof(size_t) * 2 + len + 1));
	h[0] = 1;
	h[1] = len;
	return reinterpret_cast<char*>(&h[2]);
}


char* String::Copy(const char* s)
{
	if (s)
	{
		size_t n = strlen(s);
		return reinterpret_cast<char*>(memcpy(Allocate(n), s, n + 1));
	}
	else
	{
		return nullptr;
	}
}


char* String::Copy(const char* s, size_t n)
{
	char* t = Allocate(n);
	if (s)
	{
#if defined(LINUX)
		strncpy(t, s, n);
#elif defined(WIN32)
#pragma warning(disable:4996)
		// error C4996: 'strncpy': This function or variable may be unsafe. Consider using strncpy_s instead. To disable deprecation, use _CRT_SECURE_NO_WARNINGS. See online help for details.
		strncpy(t, s, n);
#pragma warning(default:4996)
#else
#error Platform not specified.
#endif
		t[n] = '\0';
		StringLength(t) = strlen(t);
	}
	else
	{
		memset(t, 0, n + 1);
	}
	return t;
}


char* String::AddRef() const
{
	char* p = const_cast<char*>(_p);
	if (p)
	{
		ReferenceCount(p)++;
	}
	return p;
}


void String::Release()
{
	if (_p)
	{
		if (--ReferenceCount(_p) <= 0)
		{
			free(AllocatedBlock(_p));
			_p = nullptr;
		}
	}
}


String::String(const char* str)
	: _p(Copy(str))
{
}


String::String(const char* str, size_t len)
	: _p(Copy(str, len))
{
}


String::String(const String& src)
	: _p(src.AddRef())
{
}


String::~String()
{
	Release();
}


size_t String::Length() const
{
	return _p ? StringLength(_p) : 0;
}


String& String::operator = (const String& src)
{
	Release();
	_p = src.AddRef();
	return *this;
}


String& String::operator += (const String& src)
{
	if (src.Length())
	{
		if (Length())
		{
			String dst(nullptr, Length() + src.Length());
			memcpy(dst._p, _p, Length());
			memcpy(reinterpret_cast<unsigned char*>(dst._p) + Length(), src._p, src.Length());
			Release();
			_p = dst.AddRef();
		}
		else
		{
			Release();
			_p = src.AddRef();
		}
	}
	return *this;
}


bool String::operator == (const String& str) const
{
	return !strcmp(_p ? _p : "", str._p ? str._p : "");
}


bool String::operator != (const String& str) const
{
	return !!strcmp(_p ? _p : "", str._p ? str._p : "");
}


bool String::operator < (const String& str) const
{
	return strcmp(_p ? _p : "", str._p ? str._p : "") < 0;
}


bool String::operator <= (const String& str) const
{
	return strcmp(_p ? _p : "", str._p ? str._p : "") <= 0;
}


bool String::operator > (const String& str) const
{
	return strcmp(_p ? _p : "", str._p ? str._p : "") > 0;
}


bool String::operator >= (const String& str) const
{
	return strcmp(_p ? _p : "", str._p ? str._p : "") >= 0;
}


String String::Format(const char* format, ...)
{
	char buf[1];
	va_list vp;
	va_start(vp, format);
	va_list vq;
	va_copy(vq, vp);
	int n = vsnprintf(buf, sizeof(buf), format, vq);
	va_end(vq);
	if (n < 0)
	{
		va_end(vp);
		throw std::runtime_error("Failed to format a string.");
	}
	String s(nullptr, n);
	int m = vsnprintf(s, s.Length() + 1, format, vp);
	va_end(vp);
	if (m != n)
	{
		throw std::runtime_error("Unexpectedly failed to format a string.");
	}
	return s;
}


String String::Hex(const void* ptr, size_t len)
{
	String s(nullptr, len * 2);
	char* dst = s;
	const unsigned char* cur = reinterpret_cast<const unsigned char*>(ptr);
	const unsigned char* end = cur + len;
	while (cur < end)
	{
		static const char* hex = "0123456789ABCDEF";
		unsigned char b = *cur++;
		*dst++ = hex[(b >> 4) & 0xF];
		*dst++ = hex[(b >> 0) & 0xF];
	}
	return s;
}


String String::Hex(const ByteString& bs)
{
	return Hex(bs, bs.Length());
}


String String::Lowercase(const char* src)
{
	String dst(src);
#if defined(LINUX)
	const char* p = src;
	char* q = dst;
	while (*p)
	{
		*q++ = tolower(*p++);
	}
#elif defined(WIN32)
	_strlwr_s(dst, dst.Length() + 1);
#endif
	return dst;
}


String String::Uppercase(const char* src)
{
	String dst(src);
#if defined(LINUX)
	const char* p = src;
	char* q = dst;
	while (*p)
	{
		*q++ = toupper(*p++);
	}
#elif defined(WIN32)
	_strupr_s(dst, dst.Length() + 1);
#endif
	return dst;
}
