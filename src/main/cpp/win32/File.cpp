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
	: _stream(NULL)
	, _path()
	, _count(0)
{
}


File::~File()
{
	if (_stream)
	{
		fclose(_stream);
	}
}


File::operator FILE* ()
{
	return _stream;
}


File::operator bool()
{
	return _stream != NULL;
}


size_t File::Count() const
{
	return _count;
}


void File::OpenForRead(const char* path)
{
	Close();
	_path = path ? path : "[standard input]";
	_count = 0;
	int fd = -1;
	errno_t rc;
	if (path)
	{
		rc = _sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD | _S_IWRITE);
	}
	else
	{
		fd = _dup(_fileno(stdin));
		rc = (fd == -1) ? errno : 0;
	}
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), rc);
		throw std::runtime_error(String::Format("Failed to open \"%s\": %s", _path, rc ? "?" : msg));
	}
	if (!path && _setmode(fd, _O_BINARY) == -1) {
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to setmode(BINARY) to \"%s\": %s", _path, rc ? "?" : msg));
	}
	_stream = _fdopen(fd, "rb");
	if (!_stream)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to fdopen \"%s\": %s", _path, rc ? "?" : msg));
	}
}


void File::OpenForWrite(const char* path)
{
	Close();
	_path = path ? path : "[standard output]";
	_count = 0;
	int fd = -1;
	errno_t rc;
	if (path)
	{
		rc = _sopen_s(&fd, path, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _SH_DENYWR, _S_IREAD | _S_IWRITE);
	}
	else
	{
		fd = _dup(_fileno(stdout));
		rc = (fd == -1) ? errno : 0;
	}
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), rc);
		throw std::runtime_error(String::Format("Failed to create \"%s\": %s", _path, rc ? "?" : msg));
	}
	if (!path && _setmode(fd, _O_BINARY) == -1) {
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to setmode(BINARY) to \"%s\": %s", _path, rc ? "?" : msg));
	}
	_stream = _fdopen(fd, "wb");
	if (!_stream)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		_close(fd);
		throw std::runtime_error(String::Format("Failed to fdopen \"%s\": %s", _path, rc ? "?" : msg));
	}
}


void File::OpenTemporary()
{
	Close();
	_path = "[temporary file]";
	_count = 0;
	errno_t rc = tmpfile_s(&_stream);
	if (rc)
	{
		char msg[256];
		rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to open a temporary file: %s", rc ? "?" : msg));
	}
}


void File::Close()
{
	if (_stream)
	{
		bool ret = fclose(_stream) == 0;
		_stream = NULL;
		if (!ret)
		{
			char msg[256];
			errno_t rc = strerror_s(msg, sizeof(msg), errno);
			throw std::runtime_error(String::Format("Failed to close \"%s\": %s", _path, rc ? "?" : msg));
		}
	}
}


size_t File::Read(void* ptr, size_t len)
{
	size_t nbytes = fread(ptr, 1, len, _stream);
	if (ferror(_stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to read from \"%s\": %s", _path, rc ? "?" : msg));
	}
	_count += nbytes;
	return nbytes;
}


void File::Write(void* ptr, size_t len)
{
	size_t actual = fwrite(ptr, 1, len, _stream);
	if (ferror(_stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to write to \"%s\": %s", _path, rc ? "?" : msg));
	}
	_count += actual;
	if (actual != len)
	{
		throw std::runtime_error(String::Format("Failed to write to \"%s\": attempted %lu, actual %lu.", _path, len, actual));
	}
}


void File::Flush()
{
	if (fflush(_stream))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to flush to \"%s\": %s", _path, rc ? "?" : msg));
	}
}


void File::Seek(ptrdiff_t offset, int origin)
{
	if (_fseeki64(_stream, offset, origin))
	{
		throw std::runtime_error(String::Format("Failed to seek the pointer of \"%s\".", _path));
	}
}


void File::Rewind()
{
	rewind(_stream);
	_count = 0;
}


size_t File::Size()
{
	struct _stat st;
	memset(&st, 0, sizeof(st));
	if (!_fstat(_fileno(_stream), &st))
	{
		return st.st_size;
	}
	else
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to get stats from \"%s\": %s", _path, rc ? "?" : msg));
	}
}


bool File::Exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}


bool File::Delete(const char* path)
{
	return _unlink(path) == 0;
}


void File::Rename(const char* oldPath, const char* newPath)
{
	if (rename(oldPath, newPath))
	{
		char msg[256];
		errno_t rc = strerror_s(msg, sizeof(msg), errno);
		throw std::runtime_error(String::Format("Failed to rename file: %s", rc ? "?" : msg));
	}
}
