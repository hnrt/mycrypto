// Copyright (C) 2026 Hideaki Narita


#include "BCryptHashHandle.h"
#include "BCryptAlgHandle.h"
#include "Debug.h"
#include <Windows.h>
#include <bcrypt.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)
#include <stdexcept>


using namespace hnrt;


void BCryptHashHandle::Open(const BCryptAlgHandle& hAlg)
{
    Close();
    ULONG cbObjectLength = hAlg.ObjectLength;
    delete[] _p;
    _p = new UCHAR[cbObjectLength];
    NTSTATUS status = BCryptCreateHash(hAlg, &_h, _p, cbObjectLength, NULL, 0, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptCreateHash failed with status of %s.", BCryptErrorLabel(status)));
    }
    DEBUG("#Opened BCryptHash@%p\n", _h);
}


void BCryptHashHandle::Close()
{
    if (_h)
    {
        DEBUG("#Closed BCryptHash@%p\n", _h);
        BCryptDestroyHash(_h);
        _h = nullptr;
    }
    if (_p)
    {
        delete[] _p;
        _p = nullptr;
    }
}


void BCryptHashHandle::Feed(void* ptr, size_t len)
{
    NTSTATUS status = BCryptHashData(_h, reinterpret_cast<PUCHAR>(ptr), static_cast<ULONG>(len), 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptHashData(%p,%zu) failed with status of %s.", ptr, len, BCryptErrorLabel(status)));
    }
}


void BCryptHashHandle::Finalize(void* ptr, size_t len)
{
    NTSTATUS status = BCryptFinishHash(_h, reinterpret_cast<PUCHAR>(ptr), static_cast<ULONG>(len), 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptFinishHash(%p,%zu) failed with status of %s.", ptr, len, BCryptErrorLabel(status)));
    }
}
