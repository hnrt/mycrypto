// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_FILE_H
#define MYCRYPTO_FILE_H

#include <stdio.h>
#include "StringEx.h"

#if defined(LINUX)
#define DIRECTORY_SEPARATOR_CHAR '/'
#elif defined(WIN32)
#define DIRECTORY_SEPARATOR_CHAR '\\'
#else
#error Platform not specified.
#endif

namespace hnrt
{
	class File
	{
	public:

		File();
		File(const File&) = delete;
		~File();
		operator FILE* ();
		operator bool();
		size_t Count() const;
		void OpenForRead(const char* path);
		void OpenForWrite(const char* path);
		void OpenTemporary();
		void Close();
		size_t Read(void* ptr, size_t len);
		void Write(void* ptr, size_t len);
		void Flush();
		void Seek(ptrdiff_t offset, int origin);
		void Rewind();

		static bool Exists(const char* path);
		static size_t Size(const char* path);
		static bool Delete(const char* path);
		static void Rename(const char* oldPath, const char* newPath);

	private:

		FILE* stream;
		String path;
		size_t count;
	};
}

#endif //!MYCRYPTO_FILE_H
