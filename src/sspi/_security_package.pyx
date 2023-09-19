# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._security_buffer cimport FreeContextBuffer
from sspi._text cimport WideCharString, wide_char_to_str
from sspi._win32_types cimport *


cdef extern from "Security.h":
    unsigned long _SECPKG_FLAG_INTEGRITY "SECPKG_FLAG_INTEGRITY"
    unsigned long _SECPKG_FLAG_PRIVACY "SECPKG_FLAG_PRIVACY"
    unsigned long _SECPKG_FLAG_TOKEN_ONLY "SECPKG_FLAG_TOKEN_ONLY"
    unsigned long _SECPKG_FLAG_DATAGRAM "SECPKG_FLAG_DATAGRAM"
    unsigned long _SECPKG_FLAG_CONNECTION "SECPKG_FLAG_CONNECTION"
    unsigned long _SECPKG_FLAG_MULTI_REQUIRED "SECPKG_FLAG_MULTI_REQUIRED"
    unsigned long _SECPKG_FLAG_CLIENT_ONLY "SECPKG_FLAG_CLIENT_ONLY"
    unsigned long _SECPKG_FLAG_EXTENDED_ERROR "SECPKG_FLAG_EXTENDED_ERROR"
    unsigned long _SECPKG_FLAG_IMPERSONATION "SECPKG_FLAG_IMPERSONATION"
    unsigned long _SECPKG_FLAG_ACCEPT_WIN32_NAME "SECPKG_FLAG_ACCEPT_WIN32_NAME"
    unsigned long _SECPKG_FLAG_STREAM "SECPKG_FLAG_STREAM"
    unsigned long _SECPKG_FLAG_NEGOTIABLE "SECPKG_FLAG_NEGOTIABLE"
    unsigned long _SECPKG_FLAG_GSS_COMPATIBLE "SECPKG_FLAG_GSS_COMPATIBLE"
    unsigned long _SECPKG_FLAG_LOGON "SECPKG_FLAG_LOGON"
    unsigned long _SECPKG_FLAG_ASCII_BUFFERS "SECPKG_FLAG_ASCII_BUFFERS"
    unsigned long _SECPKG_FLAG_FRAGMENT "SECPKG_FLAG_FRAGMENT"
    unsigned long _SECPKG_FLAG_MUTUAL_AUTH "SECPKG_FLAG_MUTUAL_AUTH"
    unsigned long _SECPKG_FLAG_DELEGATION "SECPKG_FLAG_DELEGATION"
    unsigned long _SECPKG_FLAG_READONLY_WITH_CHECKSUM "SECPKG_FLAG_READONLY_WITH_CHECKSUM"
    unsigned long _SECPKG_FLAG_RESTRICTED_TOKENS "SECPKG_FLAG_RESTRICTED_TOKENS"
    unsigned long _SECPKG_FLAG_NEGO_EXTENDER "SECPKG_FLAG_NEGO_EXTENDER"
    unsigned long _SECPKG_FLAG_NEGOTIABLE2 "SECPKG_FLAG_NEGOTIABLE2"
    unsigned long _SECPKG_FLAG_APPCONTAINER_PASSTHROUGH "SECPKG_FLAG_APPCONTAINER_PASSTHROUGH"
    unsigned long _SECPKG_FLAG_APPCONTAINER_CHECKS "SECPKG_FLAG_APPCONTAINER_CHECKS"
    unsigned long _SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED "SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED"
    unsigned long _SECPKG_FLAG_APPLY_LOOPBACK "SECPKG_FLAG_APPLY_LOOPBACK"

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw
    SECURITY_STATUS EnumerateSecurityPackagesW(
        unsigned long *pcPackages,
        PSecPkgInfoW  *ppPackageInfo
    ) nogil

class SecurityPackageCapability(enum.IntFlag):
    SECPKG_FLAG_INTEGRITY = _SECPKG_FLAG_INTEGRITY
    SECPKG_FLAG_PRIVACY = _SECPKG_FLAG_PRIVACY
    SECPKG_FLAG_TOKEN_ONLY = _SECPKG_FLAG_TOKEN_ONLY
    SECPKG_FLAG_DATAGRAM = _SECPKG_FLAG_DATAGRAM
    SECPKG_FLAG_CONNECTION = _SECPKG_FLAG_CONNECTION
    SECPKG_FLAG_MULTI_REQUIRED = _SECPKG_FLAG_MULTI_REQUIRED
    SECPKG_FLAG_CLIENT_ONLY = _SECPKG_FLAG_CLIENT_ONLY
    SECPKG_FLAG_EXTENDED_ERROR = _SECPKG_FLAG_EXTENDED_ERROR
    SECPKG_FLAG_IMPERSONATION = _SECPKG_FLAG_IMPERSONATION
    SECPKG_FLAG_ACCEPT_WIN32_NAME = _SECPKG_FLAG_ACCEPT_WIN32_NAME
    SECPKG_FLAG_STREAM = _SECPKG_FLAG_STREAM
    SECPKG_FLAG_NEGOTIABLE = _SECPKG_FLAG_NEGOTIABLE
    SECPKG_FLAG_GSS_COMPATIBLE = _SECPKG_FLAG_GSS_COMPATIBLE
    SECPKG_FLAG_LOGON = _SECPKG_FLAG_LOGON
    SECPKG_FLAG_ASCII_BUFFERS = _SECPKG_FLAG_ASCII_BUFFERS
    SECPKG_FLAG_FRAGMENT = _SECPKG_FLAG_FRAGMENT
    SECPKG_FLAG_MUTUAL_AUTH = _SECPKG_FLAG_MUTUAL_AUTH
    SECPKG_FLAG_DELEGATION = _SECPKG_FLAG_DELEGATION
    SECPKG_FLAG_READONLY_WITH_CHECKSUM = _SECPKG_FLAG_READONLY_WITH_CHECKSUM
    SECPKG_FLAG_RESTRICTED_TOKENS = _SECPKG_FLAG_RESTRICTED_TOKENS
    SECPKG_FLAG_NEGO_EXTENDER = _SECPKG_FLAG_NEGO_EXTENDER
    SECPKG_FLAG_NEGOTIABLE2 = _SECPKG_FLAG_NEGOTIABLE2
    SECPKG_FLAG_APPCONTAINER_PASSTHROUGH = _SECPKG_FLAG_APPCONTAINER_PASSTHROUGH
    SECPKG_FLAG_APPCONTAINER_CHECKS = _SECPKG_FLAG_APPCONTAINER_CHECKS
    SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED = _SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED
    SECPKG_FLAG_APPLY_LOOPBACK = _SECPKG_FLAG_APPLY_LOOPBACK

@dataclasses.dataclass
class SecPkgInfo:
    capabilities: SecurityPackageCapability
    version: int
    rpcid: int
    max_token: int
    name: str
    comment: str

def enumerate_security_packages() -> list[SecPkgInfo]:
    cdef unsigned long num_packages = 0
    cdef PSecPkgInfoW packages = NULL

    with nogil:
        res = EnumerateSecurityPackagesW(&num_packages, &packages)

    if res:
        PyErr_SetFromWindowsErr(res)

    result = []
    try:
        for idx in range(num_packages):
            raw = packages[idx]
            info = SecPkgInfo(
                capabilities=SecurityPackageCapability(raw.fCapabilities),
                version=raw.wVersion,
                rpcid=raw.wRPCID,
                max_token=raw.cbMaxToken,
                name=wide_char_to_str(raw.Name),
                comment=wide_char_to_str(raw.Comment),
            )
            result.append(info)

    finally:
        FreeContextBuffer(packages)

    return result
