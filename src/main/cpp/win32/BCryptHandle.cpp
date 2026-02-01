// Copyright (C) 2026 Hideaki Narita


#include "BCryptHandle.h"
#include <Windows.h>
#include <bcrypt.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)
#include "StringEx.h"
#include "Array.h"
#include <stdexcept>


#pragma comment(lib, "Bcrypt")


using namespace hnrt;


String BCryptHandle::GetPropertyString(PCWSTR pszName) const
{
    Array<WCHAR> buf(260);
    while (true)
    {
        ULONG valueLength = 0UL;
        NTSTATUS status = BCryptGetProperty(_h, pszName, reinterpret_cast<PUCHAR>(&buf[0]), static_cast<ULONG>(buf.Length() * sizeof(WCHAR)), &valueLength, 0);
        if (status == STATUS_SUCCESS)
        {
            return String::Format("%S", &buf[0]);
        }
        else if (status == STATUS_BUFFER_TOO_SMALL)
        {
            buf = Array<WCHAR>(buf.Length() * 2);
        }
        else
        {
            throw std::runtime_error(String::Format("BCryptGetProperty(%S) failed with status of %s.", pszName, BCryptErrorLabel(status)));
        }
    }
}


DWORD BCryptHandle::GetPropertyDWORD(PCWSTR pszName) const
{
    DWORD dwValue = 0UL;
    ULONG valueLength = 0UL;
    NTSTATUS status = BCryptGetProperty(_h, pszName, reinterpret_cast<PUCHAR>(&dwValue), sizeof(dwValue), &valueLength, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptGetProperty(%S) failed with status of %s.", pszName, BCryptErrorLabel(status)));
    }
    else if (valueLength != sizeof(dwValue))
    {
        throw std::runtime_error(String::Format("BCryptGetProperty(%S) returned an unexpected value; actual=%lu expected=%zu", pszName, valueLength, sizeof(dwValue)));
    }
    return dwValue;
}


Array<DWORD> BCryptHandle::GetPropertyArrayDWORD(PCWSTR pszName) const
{
    Array<DWORD> buf(16);
    while (true)
    {
        ULONG valueLength = 0UL;
        NTSTATUS status = BCryptGetProperty(_h, pszName, reinterpret_cast<PUCHAR>(&buf[0]), static_cast<ULONG>(buf.Length() * sizeof(DWORD)), &valueLength, 0);
        if (status == STATUS_SUCCESS)
        {
            return valueLength < buf.Length() * sizeof(DWORD) ? Array<DWORD>(&buf[0], valueLength / sizeof(DWORD)) : buf;
        }
        else if (status == STATUS_BUFFER_TOO_SMALL)
        {
            buf = Array<DWORD>(buf.Length() * 2);
        }
        else
        {
            throw std::runtime_error(String::Format("BCryptGetProperty(%S) failed with status of %s.", pszName, BCryptErrorLabel(status)));
        }
    }
}


Array<DWORD> BCryptHandle::GetPropertyKeyLengths(PCWSTR pszName) const
{
    BCRYPT_KEY_LENGTHS_STRUCT keyLengths = { 0 };
    ULONG valueLength = 0UL;
    NTSTATUS status = BCryptGetProperty(_h, pszName, reinterpret_cast<PUCHAR>(&keyLengths), sizeof(keyLengths), &valueLength, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptGetProperty(%S) failed with status of %s.", pszName, BCryptErrorLabel(status)));
    }
    else if (valueLength != sizeof(keyLengths))
    {
        throw std::runtime_error(String::Format("BCryptGetProperty(%S) returned an unexpected value; actual=%lu expected=%zu", pszName, valueLength, sizeof(keyLengths)));
    }
    int count = 0;
    for (DWORD length = keyLengths.dwMinLength; length <= keyLengths.dwMaxLength; length += keyLengths.dwIncrement)
    {
        count++;
    }
    Array<DWORD> list(count);
    count = 0;
    for (DWORD length = keyLengths.dwMinLength; length <= keyLengths.dwMaxLength; length += keyLengths.dwIncrement)
    {
        list[count++] = length;
    }
    return list;
}


void BCryptHandle::SetProperty(PCWSTR pszName, PCWSTR pszValue) const
{
    size_t size = (wcslen(pszValue) + 1) * sizeof(WCHAR);
    NTSTATUS status = BCryptSetProperty(_h, pszName, reinterpret_cast<PUCHAR>(const_cast<PWSTR>(pszValue)), static_cast<ULONG>(size), 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptSetProperty(%S,%S) failed with status of %s.", pszName, pszValue, BCryptErrorLabel(status)));
    }
}


String hnrt::BCryptErrorLabel(NTSTATUS status)
{
    switch (status)
    {
#define CASE(x) case x: return String(#x)
    CASE(STATUS_SUCCESS);
    CASE(STATUS_AUTH_TAG_MISMATCH);
    CASE(STATUS_BUFFER_TOO_SMALL);
    CASE(STATUS_INVALID_BUFFER_SIZE);
    CASE(STATUS_INVALID_HANDLE);
    CASE(STATUS_INVALID_PARAMETER);
    CASE(STATUS_NOT_SUPPORTED);
#undef CASE
    default: return String::Format("0x%08lX", status);
    }
}
