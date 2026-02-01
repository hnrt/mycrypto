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
	stream = fopen(path, "r");
	if (!stream)
	{
		throw std::runtime_error(String::Format("Failed to open \"%s\": %s", path, strerror(errno)));
	}
	this->path = path;
	count = 0;
}


void File::OpenForWrite(const char* path)
{
	Close();
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1)
	{
		throw std::runtime_error(String::Format("Failed to create %s: %s", path, strerror(errno)));
	}
	stream = fdopen(fd, "w");
	if (!stream)
	{
		close(fd);
		throw std::runtime_error(String::Format("Failed to open %s: %s", path, strerror(errno)));
	}
	this->path = path;
	count = 0;
}


void File::OpenTemporary()
{
	Close();
	stream = tmpfile();
	if (!stream)
	{
		throw std::runtime_error(String::Format("Failed to open a temporary file: %s", strerror(errno)));
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
			throw std::runtime_error(String::Format("Failed to close %s: %s", path, strerror(errno)));
		}
	}
}


size_t File::Read(void* ptr, size_t len)
{
	size_t nbytes = fread(ptr, 1, len, stream);
	if (ferror(stream))
	{
		throw std::runtime_error(String::Format("Failed to read from %s: %s", path, strerror(errno)));
	}
	count += nbytes;
	return nbytes;
}


void File::Write(void* ptr, size_t len)
{
	size_t actual = fwrite(ptr, 1, len, stream);
	if (ferror(stream))
	{
		throw std::runtime_error(String::Format("Failed to write to %s: %s", path, strerror(errno)));
	}
	count += actual;
	if (actual != len)
	{
		throw std::runtime_error(String::Format("Failed to write to %s: attempted %lu, actual %lu.", path, len, actual));
	}
}


void File::Flush()
{
	if (fflush(stream))
	{
		throw std::runtime_error(String::Format("Failed to flush to %s: %s", path, strerror(errno)));
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
		throw std::runtime_error(String::Format("Failed to get stats from %s: %s", path, strerror(errno)));
	}
}


bool File::Delete(const char* path)
{
	return unlink(path) == 0;
}
