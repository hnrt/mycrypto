// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_ARRAY_H
#define MYCRYPTO_ARRAY_H

#include "ByteString.h"
#include <stddef.h>
#include <string.h>
#include <stdexcept>

namespace hnrt
{
	template<typename T>
	class Array
		: protected ByteString
	{
	public:
		Array(int len);
		Array(const T* ptr, int len);
		Array(const Array<T>& src);
		~Array() = default;
		int Length() const;
		Array& operator = (const Array<T>& src);
		const T& operator [](int index) const;
		T& operator [](int index);
	};

	template<typename T>
	Array<T>::Array(int len)
		: ByteString(len > 0 ? len * sizeof(T) : 0)
	{
	}

	template<typename T>
	Array<T>::Array(const T* ptr, int len)
		: ByteString(len > 0 ? len * sizeof(T) : 0)
	{
		memcpy(Ptr(), ptr, Length() * sizeof(T));
	}

	template<typename T>
	Array<T>::Array(const Array<T>& src)
		: ByteString(src)
	{
	}

	template<typename T>
	int Array<T>::Length() const
	{
		return static_cast<int>(ByteString::Length() / sizeof(T));
	}

	template<typename T>
	Array<T>& Array<T>::operator = (const Array<T>& src)
	{
		ByteString::operator = (src);
		return *this;
	}

	template<typename T>
	const T& Array<T>::operator [](int index) const
	{
		int length = Length();
		if (0 <= index && index < length)
		{
			return reinterpret_cast<const T*>(Ptr())[index];
		}
		else if (0 <= length + index && index < 0)
		{
			return reinterpret_cast<const T*>(Ptr())[length + index];
		}
		else
		{
			throw std::runtime_error("Array: Index out of range.");
		}
	}

	template<typename T>
	T& Array<T>::operator [](int index)
	{
		int length = Length();
		if (0 <= index && index < length)
		{
			return reinterpret_cast<T*>(Ptr())[index];
		}
		else if (0 <= length + index && index < 0)
		{
			return reinterpret_cast<T*>(Ptr())[length + index];
		}
		else
		{
			throw std::runtime_error("Array: Index out of range.");
		}
	}
}

#endif //!ARRAY_H
