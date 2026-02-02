// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "BCryptHandle.h"
#include "ByteString.h"

namespace hnrt
{
    class BCryptAlgHandle;

    class BCryptAuthenticatedCipherModeInfo;

    class BCryptKeyHandle
        : protected BCryptHandle
    {
    public:

        BCryptKeyHandle();
        BCryptKeyHandle(const BCryptKeyHandle&) = delete;
        virtual ~BCryptKeyHandle();
        void operator =(const BCryptKeyHandle&) = delete;
        operator BCRYPT_KEY_HANDLE() const;
        void Generate(const BCryptAlgHandle&, void*, size_t);
        void Import(const BCryptAlgHandle&, const ByteString&);
        void Close();
        ByteString Export() const;
        ByteString Encrypt(void*, size_t, void* = nullptr, size_t = 0, ULONG = 0);
        ByteString Decrypt(void*, size_t, void* = nullptr, size_t = 0, ULONG = 0);
        ByteString Encrypt(void*, size_t, BCryptAuthenticatedCipherModeInfo&, void*, size_t);
        ByteString Decrypt(void*, size_t, BCryptAuthenticatedCipherModeInfo&, void*, size_t);
        DWORD get_KeyLength() const;

        __declspec(property(get = get_KeyLength)) DWORD KeyLength;

        PUCHAR _p;
    };

    inline BCryptKeyHandle::BCryptKeyHandle()
        : BCryptHandle()
        , _p(nullptr)
    {
    }

    inline BCryptKeyHandle::~BCryptKeyHandle()
    {
        Close();
    }

    inline BCryptKeyHandle::operator BCRYPT_KEY_HANDLE() const
    {
        return _h;
    }

    inline DWORD BCryptKeyHandle::get_KeyLength() const
    {
        return GetPropertyDWORD(BCRYPT_KEY_LENGTH);
    }
}
