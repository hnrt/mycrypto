// Copyright (C) 2026 Hideaki Narita

#pragma once

#include "BCryptHandle.h"
#include <stddef.h>

namespace hnrt
{
    class BCryptAlgHandle;

    class BCryptHashHandle
        : protected BCryptHandle
    {
    public:

        BCryptHashHandle();
        BCryptHashHandle(const BCryptHashHandle&) = delete;
        virtual ~BCryptHashHandle();
        void operator =(const BCryptHashHandle&) = delete;
        operator BCRYPT_HASH_HANDLE() const;
        void Open(const BCryptAlgHandle&);
        void Close();
        void Feed(void*, size_t);
        void Finalize(void*, size_t);

    private:

        PUCHAR _p;
    };

    inline BCryptHashHandle::BCryptHashHandle()
        : BCryptHandle()
        , _p(nullptr)
    {
    }

    inline BCryptHashHandle::~BCryptHashHandle()
    {
        if (_h || _p)
        {
            Close();
        }
    }

    inline BCryptHashHandle::operator BCRYPT_HASH_HANDLE() const
    {
        return _h;
    }
}
