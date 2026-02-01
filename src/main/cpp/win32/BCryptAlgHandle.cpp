// Copyright (C) 2026 Hideaki Narita


#include "BCryptAlgHandle.h"
#include "Debug.h"
#include <Windows.h>
#include <bcrypt.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)
#include <string.h>
#include <stdexcept>


using namespace hnrt;


void BCryptAlgHandle::Open(PCWSTR pszAlgorithm)
{
    Close();
    NTSTATUS status = BCryptOpenAlgorithmProvider(&_h, pszAlgorithm, NULL, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptOpenAlgorithmProvider(%S) failed with status of %s.", pszAlgorithm, BCryptErrorLabel(status)));
    }
    DEBUG("#Opened BCryptAlgorithm@%p\n", _h);
}


void BCryptAlgHandle::Close()
{
    if (_h)
    {
        DEBUG("#Closed BCryptAlgorithm@%p\n", _h);
        BCryptCloseAlgorithmProvider(_h, 0);
        _h = nullptr;
    }
}


String BCryptAlgHandle::get_ChainingModeShort() const
{
    static const CHAR leader[] = { "ChainingMode" };
    static size_t leaderLength = strlen(leader);
    String value = GetPropertyString(BCRYPT_CHAINING_MODE);
    return !strncmp(value, leader, leaderLength) ? String(value.Ptr() + leaderLength) : value;
}
