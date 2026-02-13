// Copyright (C) 2026 Hideaki Narita


#include "File.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
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
	int fd = path ? open(path, O_RDONLY) : dup(fileno(stdin));
	if (fd == -1)
	{
		throw std::runtime_error(String::Format("Failed to open \"%s\": %s", _path, strerror(errno)));
	}
	_stream = fdopen(fd, "r");
	if (!_stream)
	{
		close(fd);
		throw std::runtime_error(String::Format("Failed to open \"%s\": %s", _path, strerror(errno)));
	}
}


void File::OpenForWrite(const char* path)
{
	Close();
	_path = path ? path : "[standard output]";
	_count = 0;
	int fd = path ? open(path, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) : dup(fileno(stdout));
	if (fd == -1)
	{
		throw std::runtime_error(String::Format("Failed to create %s: %s", _path, strerror(errno)));
	}
	_stream = fdopen(fd, "w");
	if (!_stream)
	{
		close(fd);
		throw std::runtime_error(String::Format("Failed to open %s: %s", _path, strerror(errno)));
	}
}


void File::OpenTemporary()
{
	Close();
	_path = "[temporary file]";
	_count = 0;
	_stream = tmpfile();
	if (!_stream)
	{
		throw std::runtime_error(String::Format("Failed to open a temporary file: %s", strerror(errno)));
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
			throw std::runtime_error(String::Format("Failed to close %s: %s", _path, strerror(errno)));
		}
	}
}


size_t File::Read(void* ptr, size_t len)
{
	size_t nbytes = fread(ptr, 1, len, _stream);
	if (ferror(_stream))
	{
		throw std::runtime_error(String::Format("Failed to read from %s: %s", _path, strerror(errno)));
	}
	_count += nbytes;
	return nbytes;
}


void File::Write(void* ptr, size_t len)
{
	size_t actual = fwrite(ptr, 1, len, _stream);
	if (ferror(_stream))
	{
		throw std::runtime_error(String::Format("Failed to write to %s: %s", _path, strerror(errno)));
	}
	_count += actual;
	if (actual != len)
	{
		throw std::runtime_error(String::Format("Failed to write to %s: attempted %lu, actual %lu.", _path, len, actual));
	}
}


void File::Flush()
{
	if (fflush(_stream))
	{
		throw std::runtime_error(String::Format("Failed to flush to %s: %s", _path, strerror(errno)));
	}
}


void File::Seek(ptrdiff_t offset, int origin)
{
	if (fseek(_stream, offset, origin))
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
	struct stat st;
	memset(&st, 0, sizeof(st));
	if (!fstat(fileno(_stream), &st))
	{
		return st.st_size;
	}
	else
	{
		throw std::runtime_error(String::Format("Failed to get stats from %s: %s", _path, strerror(errno)));
	}
}


bool File::Exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}


bool File::Delete(const char* path)
{
	return unlink(path) == 0;
}


void File::Rename(const char* oldPath, const char* newPath)
{
	if (rename(oldPath, newPath))
	{
		throw std::runtime_error(String::Format("Failed to rename file: %s", strerror(errno)));
	}
}
