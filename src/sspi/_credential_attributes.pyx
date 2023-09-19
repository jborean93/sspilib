# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from cpython.exc cimport PyErr_SetFromWindowsErr
from cpython.unicode cimport PyUnicode_GET_LENGTH
from libc.stdlib cimport free, malloc

from sspi._credential cimport Credential
from sspi._text cimport WideCharString, wide_char_to_str
from sspi._win32_types cimport *


cdef extern from "Security.h":
    unsigned long SECPKG_CRED_ATTR_NAMES
    unsigned long SECPKG_CRED_ATTR_SSI_PROVIDER
    unsigned long SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS
    unsigned long SECPKG_CRED_ATTR_CERT
    unsigned long SECPKG_CRED_ATTR_PAC_BYPASS

    unsigned long KDC_PROXY_SETTINGS_V1
    unsigned long _KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY "KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY"

    cdef struct _SecPkgCredentials_KdcProxySettingsW:
        ULONG Version
        ULONG Flags
        USHORT ProxyServerOffset
        USHORT ProxyServerLength
        USHORT ClientTlsCredOffset
        USHORT ClientTlsCredLength
    ctypedef _SecPkgCredentials_KdcProxySettingsW SecPkgCredentials_KdcProxySettingsW
    ctypedef SecPkgCredentials_KdcProxySettingsW *PSecPkgCredentials_KdcProxySettingsW

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesw
    SECURITY_STATUS SetCredentialsAttributesW(
        PCredHandle   phCredential,
        unsigned long ulAttribute,
        void          *pBuffer,
        unsigned long cbBuffer
    ) nogil


class KdcProxySettingsFlags(enum.IntEnum):
    KDX_PROXY_SETTINGS_FLAGS_NONE = 0
    KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY = _KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY

cdef class SecPkgCred:

    cdef (unsigned long, void *, unsigned long) __c_value__(SecPkgCred self):
        return (0, NULL, 0)

cdef class SecPkgCredKdcProxySettings(SecPkgCred):
    cdef PSecPkgCredentials_KdcProxySettingsW raw

    def __cinit__(
        SecPkgCredKdcProxySettings self,
        *,
        flags: KdcProxySettingsFlags | int = 0,
        proxy_server: str | None = None,
    ):
        cdef WideCharString proxy_wchar = WideCharString(proxy_server)
        cdef int proxy_wchar_len = proxy_wchar.length * sizeof(wchar_t)
        cdef unsigned char[:] temp_ptr = None

        raw_length = sizeof(SecPkgCredentials_KdcProxySettingsW) + proxy_wchar_len
        self.raw = <PSecPkgCredentials_KdcProxySettingsW>malloc(raw_length)
        if not self.raw:
            raise MemoryError("Cannot malloc SecPkgCredKdcProxySettings buffers")

        cdef unsigned char[:] raw_ptr = <unsigned char[:raw_length]><unsigned char*>self.raw
        offset = sizeof(SecPkgCredentials_KdcProxySettingsW)

        self.raw.Version = KDC_PROXY_SETTINGS_V1
        self.raw.Flags = flags

        self.raw.ProxyServerOffset = 0
        self.raw.ProxyServerLength = proxy_wchar_len
        if proxy_wchar_len:
            self.raw.ProxyServerOffset = offset

            temp_ptr = <unsigned char[:proxy_wchar_len]><unsigned char*>proxy_wchar.raw
            raw_ptr[offset:offset + proxy_wchar_len] = temp_ptr.copy()
            offset += proxy_wchar_len

        self.raw.ClientTlsCredOffset = 0
        self.raw.ClientTlsCredLength = 0

    def __dealloc__(SecPkgCredKdcProxySettings self):
        if self.raw:
            free(self.raw)
            self.raw = NULL

    cdef (unsigned long, void *, unsigned long) __c_value__(SecPkgCredKdcProxySettings self):
        cdef unsigned long length = sizeof(SecPkgCredentials_KdcProxySettingsW) + \
            self.raw.ProxyServerLength + \
            self.raw.ClientTlsCredLength
        return (SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS, self.raw, length)

    def __repr__(SecPkgCredKdcProxySettings self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'flags': self.flags,
            'proxy_server': repr(self.proxy_server),
        }.items()]

        return f"SecPkgCredKdcProxySettings({', '.join(kwargs)})"

    @property
    def version(SecPkgCredKdcProxySettings self) -> int:
        return self.raw.Version

    @property
    def flags(SecPkgCredKdcProxySettings self) -> KdcProxySettingsFlags:
        return KdcProxySettingsFlags(self.raw.Flags)

    @property
    def proxy_server(SecPkgCredKdcProxySettings self) -> str | None:
        cdef const wchar_t *raw = NULL
        cdef int size = -1

        cdef unsigned char [:] raw_view = None
        if self.raw.ProxyServerOffset and self.raw.ProxyServerLength:
            raw_view = <unsigned char [:self.raw.ProxyServerOffset + self.raw.ProxyServerLength]> \
                <unsigned char*>self.raw

            raw = <wchar_t*>&raw_view[self.raw.ProxyServerOffset]
            size = self.raw.ProxyServerLength // sizeof(wchar_t)

        return wide_char_to_str(raw, size)

def set_credentials_attributes(
    Credential credential not None,
    SecPkgCred attribute not None,
) -> None:
    cdef (unsigned long, void*, unsigned long) raw = attribute.__c_value__()

    with nogil:
        res = SetCredentialsAttributesW(
            &credential.raw,
            raw[0],
            raw[1],
            raw[2],
        )

    if res:
        PyErr_SetFromWindowsErr(res)
