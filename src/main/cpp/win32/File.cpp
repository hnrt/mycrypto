// Copyright (C) 2026 Hideaki Narita


#include "File.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <io.h>
#include <stdexcept>


using namespace hnrt;


File::File()
	: stream(NULL)
	, path()
	, count(0)
{
}


File::~File()
{
	if (stream)
	{
		fclose(stream);
	}
}


File::operator FILE* ()
{
	return stream;
}


File::operator bool()
{
	return stream != NULL;
}


size_t File::Count() const
{
	return count;
}


void File::OpenForRead(const char* path)
{
	Close();
	int fd = -1;
	errno_t rc = _sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD | _S_IWRITE);
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), rc);
		throw std::runtime_error(String::Format("Failed to open \"%s\": %s", path, rc ? "?" : msg));
	}
	stream = _fdopen(fd, "rb");
	if (!stream)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to fdopen \"%s\": %s", path, rc ? "?" : msg));
	}
	this->path = path;
	count = 0;
}


void File::OpenForWrite(const char* path)
{
	Close();
	int fd = -1;
	errno_t rc = _sopen_s(&fd, path, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _SH_DENYWR, _S_IREAD | _S_IWRITE);
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), rc);
		throw std::runtime_error(String::Format("Failed to create \"%s\": %s", path, rc ? "?" : msg));
	}
	stream = _fdopen(fd, "wb");
	if (!stream)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to fdopen \"%s\": %s", path, rc ? "?" : msg));
	}
	this->path = path;
	count = 0;
}


void File::OpenTemporary()
{
	Close();
	errno_t rc = tmpfile_s(&stream);
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to open a temporary file: %s", rc ? "?" : msg));
	}
	path = "(temporary file)";
	count = 0;
}


void File::Close()
{
	if (stream)
	{
		bool ret = fclose(stream) == 0;
		stream = NULL;
		if (!ret)
		{
			char msg[256];
			errno_t rc = strerror_s(msg, sizeof(msg), errno);
			throw std::runtime_error(String::Format("Failed to close \"%s\": %s", path, rc ? "?" : msg));
		}
	}
}


size_t File::Read(void* ptr, size_t len)
{
	size_t nbytes = fread(ptr, 1, len, stream);
	if (ferror(stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to read from \"%s\": %s", path, rc ? "?" : msg));
	}
	count += nbytes;
	return nbytes;
}


void File::Write(void* ptr, size_t len)
{
	size_t actual = fwrite(ptr, 1, len, stream);
	if (ferror(stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to write to \"%s\": %s", path, rc ? "?" : msg));
	}
	count += actual;
	if (actual != len)
	{
		throw std::runtime_error(String::Format("Failed to write to \"%s\": attempted %lu, actual %lu.", path, len, actual));
	}
}


void File::Flush()
{
	if (fflush(stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to flush to \"%s\": %s", path, rc ? "?" : msg));
	}
}


void File::Rewind()
{
	rewind(stream);
	count = 0;
}


bool File::Exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}


size_t File::Size(const char* path)
{
	struct stat st;
	memset(&st, 0, sizeof(st));
	if (!stat(path, &st))
	{
		return st.st_size;
	}
	else
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to get stats from \"%s\": %s", path, rc ? "?" : msg));
	}
}


bool File::Delete(const char* path)
{
	return _unlink(path) == 0;
}
