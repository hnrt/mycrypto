// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_STRINGEX_H
#define MYCRYPTO_STRINGEX_H

#include <stddef.h>

namespace hnrt
{
	class ByteString;

	class String
	{
	public:

		String(const char* str = nullptr);
		String(const char* str, size_t len);
		String(const String& src);
		~String();
		const char* Ptr() const;
		char* Ptr();
		size_t Length() const;
		String& operator = (const String& src);
		String& operator += (const String& src);
		operator const char* () const;
		operator char* ();
		operator bool() const;
		bool operator == (const String& str) const;
		bool operator != (const String& str) const;
		bool operator < (const String & str) const;
		bool operator <= (const String& str) const;
		bool operator > (const String& str) const;
		bool operator >= (const String& str) const;

		static String Format(const char* format, ...);
		static String Hex(const void* ptr, size_t len);
		static String Hex(const ByteString& bs);
		static String Lowercase(const char* src);
		static String Uppercase(const char* src);

	private:

		char* AddRef() const;
		void Release();

		static char* Allocate(size_t len);
		static char* Copy(const char* s);
		static char* Copy(const char* s, size_t n);

		char* _p;
	};

	inline const char* String::Ptr() const
	{
		return _p;
	}

	inline char* String::Ptr()
	{
		return _p;
	}

	inline String::operator const char* () const
	{
		return _p;
	}

	inline String::operator char* ()
	{
		return _p;
	}

	inline String::operator bool() const
	{
		return _p ? true : false;
	}
}

#endif //!MYCRYPTO_STRINGEX_H
