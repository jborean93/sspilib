# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import collections
import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._security_buffer cimport FreeContextBuffer
from sspi._security_context cimport PCtxtHandle, SecurityContext
from sspi._text cimport wide_char_to_str
from sspi._win32_types cimport *

from sspi._ntstatus import NtStatus


cdef extern from "Security.h":
    unsigned long SECPKG_ATTR_SIZES
    unsigned long SECPKG_ATTR_NAMES
    unsigned long SECPKG_ATTR_LIFESPAN
    unsigned long SECPKG_ATTR_DCE_INFO
    unsigned long SECPKG_ATTR_STREAM_SIZES
    unsigned long SECPKG_ATTR_KEY_INFO
    unsigned long SECPKG_ATTR_AUTHORITY
    unsigned long SECPKG_ATTR_PROTO_INFO
    unsigned long SECPKG_ATTR_PASSWORD_EXPIRY
    unsigned long SECPKG_ATTR_SESSION_KEY
    unsigned long SECPKG_ATTR_PACKAGE_INFO
    unsigned long SECPKG_ATTR_USER_FLAGS
    unsigned long SECPKG_ATTR_NEGOTIATION_INFO
    unsigned long SECPKG_ATTR_NATIVE_NAMES
    unsigned long SECPKG_ATTR_FLAGS
    unsigned long SECPKG_ATTR_USE_VALIDATED
    unsigned long SECPKG_ATTR_CREDENTIAL_NAME
    unsigned long SECPKG_ATTR_TARGET_INFORMATION
    unsigned long SECPKG_ATTR_ACCESS_TOKEN
    unsigned long SECPKG_ATTR_TARGET
    unsigned long SECPKG_ATTR_AUTHENTICATION_ID
    unsigned long SECPKG_ATTR_LOGOFF_TIME
    unsigned long SECPKG_ATTR_NEGO_KEYS
    unsigned long SECPKG_ATTR_PROMPTING_NEEDED
    unsigned long SECPKG_ATTR_UNIQUE_BINDINGS
    unsigned long SECPKG_ATTR_ENDPOINT_BINDINGS
    unsigned long SECPKG_ATTR_CLIENT_SPECIFIED_TARGET
    unsigned long SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS
    unsigned long SECPKG_ATTR_NEGO_PKG_INFO
    unsigned long SECPKG_ATTR_NEGO_STATUS
    unsigned long SECPKG_ATTR_CONTEXT_DELETED
    unsigned long SECPKG_ATTR_DTLS_MTU
    unsigned long SECPKG_ATTR_DATAGRAM_SIZES
    unsigned long SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES
    unsigned long SECPKG_ATTR_APPLICATION_PROTOCOL
    unsigned long SECPKG_ATTR_NEGOTIATED_TLS_EXTENSIONS
    unsigned long SECPKG_ATTR_IS_LOOPBACK

    cdef struct _SecPkgContext_NamesW:
        LPWSTR sUserName
    ctypedef _SecPkgContext_NamesW SecPkgContext_NamesW
    ctypedef SecPkgContext_NamesW *PSecPkgContext_NamesW

    cdef struct _SecPkgContext_Sizes:
        unsigned long cbMaxToken
        unsigned long cbMaxSignature
        unsigned long cbBlockSize
        unsigned long cbSecurityTrailer
    ctypedef _SecPkgContext_Sizes SecPkgContext_Sizes
    ctypedef SecPkgContext_Sizes *PSecPkgContext_Sizes

    cdef struct _SecPkgContext_SessionKey:
        unsigned long SessionKeyLength
        unsigned char *SessionKey
    ctypedef _SecPkgContext_SessionKey SecPkgContext_SessionKey
    ctypedef SecPkgContext_SessionKey *PSecPkgContext_SessionKey

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw
    SECURITY_STATUS QueryContextAttributesW(
        PCtxtHandle   phContext,
        unsigned long ulAttribute,
        void          *pBuffer
    ) nogil

cdef class SecPkgBuffer:

    cdef (unsigned long, void *) __c_value__(SecPkgBuffer self):
        return (0, NULL)

cdef class SecPkgContextNames(SecPkgBuffer):
    cdef SecPkgContext_NamesW raw

    def __dealloc__(SecPkgContextNames self):
        if self.raw.sUserName:
            FreeContextBuffer(self.raw.sUserName)
            self.raw.sUserName = NULL

    cdef (unsigned long, void *) __c_value__(SecPkgContextNames self):
        return (SECPKG_ATTR_NAMES, &self.raw)

    def __repr__(SecPkgContextNames self):
        return f"SecPkgContextNames(username={self.username!r})"

    @property
    def username(SecPkgContextNames self) -> str:
        if self.raw.sUserName == NULL:
            return ""
        else:
            return wide_char_to_str(self.raw.sUserName)

cdef class SecPkgContextSessionKey(SecPkgBuffer):
    cdef SecPkgContext_SessionKey raw

    def __dealloc__(SecPkgContextSessionKey self):
        if self.raw.SessionKey:
            FreeContextBuffer(self.raw.SessionKey)
            self.raw.SessionKeyLength = 0
            self.raw.SessionKey = NULL

    cdef (unsigned long, void *) __c_value__(SecPkgContextSessionKey self):
        return (SECPKG_ATTR_SESSION_KEY, &self.raw)

    def __repr__(SecPkgContextSessionKey self):
        return f"SecPkgContextSessionKey(session_key={self.session_key!r})"

    @property
    def session_key(SecPkgContextSessionKey self) -> bytes:
        if self.raw.SessionKeyLength and self.raw.SessionKey != NULL:
            return (<char *>self.raw.SessionKey)[:self.raw.SessionKeyLength]
        else:
            return b""

cdef class SecPkgContextSizes(SecPkgBuffer):
    cdef SecPkgContext_Sizes raw

    cdef (unsigned long, void *) __c_value__(SecPkgContextSizes self):
        return (SECPKG_ATTR_SIZES, &self.raw)

    def __repr__(SecPkgContextSizes self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'max_token': self.max_token,
            'max_signature': self.max_signature,
            'block_size': self.block_size,
            'security_trailer': self.security_trailer,
        }.items()]

        return f"SecPkgContextSizes({', '.join(kwargs)})"

    @property
    def max_token(SecPkgContextSizes self) -> int:
        return self.raw.cbMaxToken

    @property
    def max_signature(SecPkgContextSizes self) -> int:
        return self.raw.cbMaxSignature

    @property
    def block_size(SecPkgContextSizes self) -> int:
        return self.raw.cbBlockSize

    @property
    def security_trailer(SecPkgContextSizes self) -> int:
        return self.raw.cbSecurityTrailer

def query_context_attributes(
    SecurityContext context not None,
    type attribute not None,
) -> SecPkgBuffer:
    if not issubclass(attribute, SecPkgBuffer):
        raise TypeError("attribute must be a type of SecPkgBuffer")

    cdef SecPkgBuffer value = attribute()
    cdef (unsigned long, void*) raw = value.__c_value__()

    with nogil:
        res = QueryContextAttributesW(
            &context.raw,
            raw[0],
            raw[1],
        )

    if res:
        PyErr_SetFromWindowsErr(res)

    return value
