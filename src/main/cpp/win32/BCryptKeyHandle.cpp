// Copyright (C) 2026 Hideaki Narita


#include "BCryptKeyHandle.h"
#include "BCryptAlgHandle.h"
#include "BCryptAuthenticatedCipherModeInfo.h"
#include "Debug.h"
#include <Windows.h>
#include <bcrypt.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)
#include <stdexcept>


using namespace hnrt;


void BCryptKeyHandle::Generate(const BCryptAlgHandle& hAlg, void* pKey, size_t cbKey)
{
    Close();
    DWORD dwObjectLength = hAlg.ObjectLength;
    delete[] _p;
    _p = new UCHAR[dwObjectLength];
    NTSTATUS status = BCryptGenerateSymmetricKey(hAlg, &_h, _p, dwObjectLength, reinterpret_cast<PUCHAR>(pKey), static_cast<ULONG>(cbKey), 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptGenerateSymmetricKey(%p,%zu) failed with status of %s.", pKey, cbKey, BCryptErrorLabel(status)));
    }
    DEBUG("#Opened BCryptKey@%p by Generate\n", _h);
}


void BCryptKeyHandle::Import(const BCryptAlgHandle& hAlg, const ByteString& keyBlob)
{
    Close();
    DWORD dwObjectLength = hAlg.ObjectLength;
    delete[] _p;
    _p = new UCHAR[dwObjectLength];
    NTSTATUS status = BCryptImportKey(hAlg, NULL, BCRYPT_OPAQUE_KEY_BLOB, &_h, _p, dwObjectLength, const_cast<PUCHAR>(reinterpret_cast<const unsigned char*>(keyBlob.Ptr())), static_cast<ULONG>(keyBlob.Length()), 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptImportKey failed with status of %s.", BCryptErrorLabel(status)));
    }
    DEBUG("#Opened BCryptKey@%p by Import\n", _h);
}


void BCryptKeyHandle::Close()
{
    if (_h)
    {
        DEBUG("#Closed BCryptKey@%p\n", _h);
        BCryptDestroyKey(_h);
        _h = nullptr;
    }
    if (_p)
    {
        delete[] _p;
        _p = nullptr;
    }
}


ByteString BCryptKeyHandle::Export() const
{
    ULONG cbKeyBlob = ~0;
    NTSTATUS status = BCryptExportKey(_h, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &cbKeyBlob, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptExportKey(OPAQUE_KEY_BLOB) failed with status of %s.", BCryptErrorLabel(status)));
    }
    ByteString keyBlob(cbKeyBlob);
    status = BCryptExportKey(_h, NULL, BCRYPT_OPAQUE_KEY_BLOB, keyBlob, cbKeyBlob, &cbKeyBlob, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptExportKey(OPAQUE_KEY_BLOB,%p,%lu) failed with status of %s.", keyBlob, cbKeyBlob, BCryptErrorLabel(status)));
    }
    return keyBlob;
}


ByteString BCryptKeyHandle::Encrypt(void* pData, size_t cbData, void* pIV, size_t cbIV, ULONG dwFlags)
{
    ULONG cbCipherText = ~0;
    NTSTATUS status = BCryptEncrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), NULL, 0, &cbCipherText, dwFlags);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptEncrypt(%p,%zu,%p,%zu) failed with status of %s.", pData, cbData, pIV, cbIV, BCryptErrorLabel(status)));
    }
    ByteString encrypted(cbCipherText);
    status = BCryptEncrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), encrypted, cbCipherText, &cbCipherText, dwFlags);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptEncrypt(%p,%zu,%p,%zu,%lu) failed with status of %s.", pData, cbData, pIV, cbIV, cbCipherText, BCryptErrorLabel(status)));
    }
    return encrypted;
}


ByteString BCryptKeyHandle::Decrypt(void* pData, size_t cbData, void* pIV, size_t cbIV, ULONG dwFlags)
{
    ULONG cbPlainText = ~0;
    NTSTATUS status = BCryptDecrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), NULL, 0, &cbPlainText, dwFlags);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptDecrypt(%p,%zu,%p,%zu) failed with status of %s.", pData, cbData, pIV, cbIV, BCryptErrorLabel(status)));
    }
    ByteString decrypted(cbPlainText);
    status = BCryptDecrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), decrypted, cbPlainText, &cbPlainText, dwFlags);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptDecrypt(%p,%zu,%p,%zu,%lu) failed with status of %s.", pData, cbData, pIV, cbIV, cbPlainText, BCryptErrorLabel(status)));
    }
    return decrypted;
}


ByteString BCryptKeyHandle::Encrypt(void* pData, size_t cbData, BCryptAuthenticatedCipherModeInfo& info, void* pIV, size_t cbIV)
{
    ULONG cbCipherText = ~0;
    NTSTATUS status = BCryptEncrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, NULL, 0, NULL, 0, &cbCipherText, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptEncrypt(%p,%zu) failed with status of %s.", pData, cbData, BCryptErrorLabel(status)));
    }
    ByteString encrypted(cbCipherText);
    status = BCryptEncrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), &info, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), encrypted, cbCipherText, &cbCipherText, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptEncrypt(%p,%zu,%lu) failed with status of %s.", pData, cbData, cbCipherText, BCryptErrorLabel(status)));
    }
    return encrypted;
}


ByteString BCryptKeyHandle::Decrypt(void* pData, size_t cbData, BCryptAuthenticatedCipherModeInfo& info, void* pIV, size_t cbIV)
{
    ULONG cbPlainText = ~0;
    NTSTATUS status = BCryptDecrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), NULL, NULL, 0, NULL, 0, &cbPlainText, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptDecrypt(%p,%zu) failed with status of %s.", pData, cbData, BCryptErrorLabel(status)));
    }
    ByteString decrypted(cbPlainText);
    status = BCryptDecrypt(_h, reinterpret_cast<PUCHAR>(pData), static_cast<ULONG>(cbData), &info, reinterpret_cast<PUCHAR>(pIV), static_cast<ULONG>(cbIV), decrypted, cbPlainText, &cbPlainText, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error(String::Format("BCryptDecrypt(%p,%zu,%lu) failed with status of %s.", pData, cbData, cbPlainText, BCryptErrorLabel(status)));
    }
    return decrypted;
}
