// Copyright (C) 2026 Hideaki Narita


#include "ByteString.h"
#include "Heap.h"
#include "StringEx.h"
#include <string.h>
#include <stdlib.h>
#include <stdexcept>


using namespace hnrt;


inline static void* AllocatedBlock(void* p)
{
	return &reinterpret_cast<size_t*>(p)[-2];
}


inline static size_t& ReferenceCount(void* p)
{
	return reinterpret_cast<size_t*>(p)[-2];
}


inline static size_t& ByteLength(void* p)
{
	return reinterpret_cast<size_t*>(p)[-1];
}


void* ByteString::Allocate(size_t len)
{
	size_t* h = reinterpret_cast<size_t*>(hnrt::Allocate(sizeof(size_t) * 2 + len));
	h[0] = 1;
	h[1] = len;
	return &h[2];
}


void* ByteString::AddRef() const
{
	void* p = const_cast<void*>(_p);
	if (p)
	{
		ReferenceCount(p)++;
	}
	return p;
}


void ByteString::Release()
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


ByteString::ByteString(size_t len)
	: _p(len ? Allocate(len) : nullptr)
{
}


ByteString::ByteString(const void* ptr, size_t len)
	: _p(ptr ? memcpy(Allocate(len), ptr, len) : len ? memset(Allocate(len), 0, len) : nullptr)
{
}


ByteString::ByteString(const ByteString& src)
	: _p(src.AddRef())
{
}


ByteString::~ByteString()
{
	Release();
}


size_t ByteString::Length() const
{
	return _p ? ByteLength(_p) : 0;
}


ByteString& ByteString::operator = (const ByteString& src)
{
	Release();
	_p = src.AddRef();
	return *this;
}


ByteString& ByteString::operator += (const ByteString& src)
{
	size_t length2 = src.Length();
	if (length2)
	{
		size_t length1 = Length();
		ByteString result(length1 + length2);
		memcpy(result._p, _p, length1);
		memcpy(reinterpret_cast<unsigned char*>(result._p) + length1, src._p, length2);
		Release();
		_p = result.AddRef();
	}
	return *this;
}


static signed char HEX_MAP[256] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 00-0F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 10-1F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 20-2F
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 30-3F
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 40-4F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 50-5F
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 60-6F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 70-7F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-8F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 90-9F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // A0-AF
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // B0-BF
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // C0-CF
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // D0-DF
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // E0-EF
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // F0-FF
};


ByteString ByteString::ParseHex(const char* s)
{
	const char* t = s;
	while (*t)
	{
		int c = *t++ & 0xFF;
		if (HEX_MAP[c] < 0)
		{
			throw std::runtime_error(String::Format("Parse error at %d: %s", static_cast<int>(t - s) - 1, s).Ptr());
		}
	}
	size_t n = t - s;
	if ((n & 1))
	{
		throw std::runtime_error(String::Format("Premature end of string: %s", s).Ptr());
	}
	ByteString result(n / 2);
	unsigned char* d = result;
	for (t = s; *t; t += 2)
	{
		*d++ =
			static_cast<unsigned char>(HEX_MAP[static_cast<unsigned char>(t[0])] << 4) |
			static_cast<unsigned char>(HEX_MAP[static_cast<unsigned char>(t[1])] << 0);
	}
	return result;
}


ByteString hnrt::operator + (const ByteString& src1, const ByteString& src2)
{
	size_t length1 = src1.Length();
	size_t length2 = src2.Length();
	ByteString result(length1 + length2);
	if (result.Length())
	{
		memcpy((unsigned char*)result, src1, length1);
		memcpy((unsigned char*)result + length1, src2, length2);
	}
	return result;
}
