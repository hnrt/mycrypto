// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_BYTESTRING_H
#define MYCRYPTO_BYTESTRING_H

#include <stddef.h>

namespace hnrt
{
	class ByteString
	{
	public:

		ByteString(size_t len = 0);
		ByteString(const void* ptr, size_t len);
		ByteString(const ByteString& src);
		~ByteString();
		const void* Ptr() const;
		void* Ptr();
		size_t Length() const;
		ByteString& operator = (const ByteString& src);
		ByteString& operator += (const ByteString& src);
		operator const unsigned char* () const;
		operator unsigned char* ();
		operator bool() const;
		ByteString Pkcs7Padding(int blockLength) const;

		static ByteString ParseHex(const char* s);

	private:

		void* AddRef() const;
		void Release();

		static void* Allocate(size_t len);

		void* _p;
	};

	inline const void* ByteString::Ptr() const
	{
		return _p;
	}

	inline void* ByteString::Ptr()
	{
		return _p;
	}

	inline ByteString::operator const unsigned char* () const
	{
		return reinterpret_cast<const unsigned char*>(_p);
	}

	inline ByteString::operator unsigned char* ()
	{
		return reinterpret_cast<unsigned char*>(_p);
	}

	inline ByteString::operator bool() const
	{
		return _p ? true : false;
	}

	ByteString operator + (const ByteString& src1, const ByteString& src2);
}

#endif //!MYCRYPTO_BYTESTRING_H
