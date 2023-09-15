# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._text cimport WideCharString
from sspi._win32_types cimport *


cdef extern from "Security.h":
    unsigned long _SECPKG_CRED_INBOUND "SECPKG_CRED_INBOUND"
    unsigned long _SECPKG_CRED_OUTBOUND "SECPKG_CRED_OUTBOUND"
    unsigned long _SECPKG_CRED_BOTH "SECPKG_CRED_BOTH"
    unsigned long _SECPKG_CRED_AUTOLOGON_RESTRICTED "SECPKG_CRED_AUTOLOGON_RESTRICTED"
    unsigned long _SECPKG_CRED_PROCESS_POLICY_ONLY "SECPKG_CRED_PROCESS_POLICY_ONLY"

    unsigned long _SEC_WINNT_AUTH_IDENTITY_ANSI "SEC_WINNT_AUTH_IDENTITY_ANSI"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_UNICODE "SEC_WINNT_AUTH_IDENTITY_UNICODE"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_MARSHALLED "SEC_WINNT_AUTH_IDENTITY_MARSHALLED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_ONLY "SEC_WINNT_AUTH_IDENTITY_ONLY"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED "SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER "SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN "SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN"
    unsigned long _SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER "SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER"

    unsigned long SEC_WINNT_AUTH_IDENTITY_VERSION
    unsigned long SEC_WINNT_AUTH_IDENTITY_VERSION_2

    cdef struct _SEC_WINNT_AUTH_IDENTITY_EXW:
        unsigned long Version;
        unsigned long Length;
        unsigned short *User;
        unsigned long UserLength;
        unsigned short *Domain;
        unsigned long DomainLength;
        unsigned short *Password;
        unsigned long PasswordLength;
        unsigned long Flags;
        unsigned short *PackageList;
        unsigned long PackageListLength;
    ctypedef _SEC_WINNT_AUTH_IDENTITY_EXW SEC_WINNT_AUTH_IDENTITY_EXW
    ctypedef SEC_WINNT_AUTH_IDENTITY_EXW *PSEC_WINNT_AUTH_IDENTITY_EXW

    ctypedef void (*SEC_GET_KEY_FN)(
        void *Arg,
        void *Principal,
        unsigned long KeyVer,
        void **Key,
        SECURITY_STATUS *Status,
    )

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew
    SECURITY_STATUS AcquireCredentialsHandleW(
        LPWSTR         pPrincipal,
        LPWSTR         pPackage,
        unsigned long  fCredentialUse,
        void           *pvLogonId,
        void           *pAuthData,
        SEC_GET_KEY_FN pGetKeyFn,
        void           *pvGetKeyArgument,
        PCredHandle    phCredential,
        PTimeStamp     ptsExpiry
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-freecredentialshandle
    SECURITY_STATUS FreeCredentialsHandle(
        PCredHandle phCredential
    ) nogil

class CredentialUse(enum.IntFlag):
    SECPKG_CRED_INBOUND = _SECPKG_CRED_INBOUND
    SECPKG_CRED_OUTBOUND = _SECPKG_CRED_OUTBOUND
    SECPKG_CRED_BOTH = _SECPKG_CRED_BOTH
    SECPKG_CRED_AUTOLOGON_RESTRICTED = _SECPKG_CRED_AUTOLOGON_RESTRICTED
    SECPKG_CRED_PROCESS_POLICY_ONLY = _SECPKG_CRED_PROCESS_POLICY_ONLY

class WinNTAuthFlags(enum.IntFlag):
    SEC_WINNT_AUTH_IDENTITY_ANSI = _SEC_WINNT_AUTH_IDENTITY_ANSI
    SEC_WINNT_AUTH_IDENTITY_UNICODE = _SEC_WINNT_AUTH_IDENTITY_UNICODE
    SEC_WINNT_AUTH_IDENTITY_MARSHALLED = _SEC_WINNT_AUTH_IDENTITY_MARSHALLED
    SEC_WINNT_AUTH_IDENTITY_ONLY = _SEC_WINNT_AUTH_IDENTITY_ONLY
    SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED = _SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED = _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED
    SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED = _SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED = _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED
    SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED = _SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER = _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN = _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN
    SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER = _SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER

cdef class Credential:
    # cdef CredHandle handle
    # cdef TimeStamp raw_expiry
    # cdef int needs_free

    def __dealloc__(Credential self):
        if self.needs_free:
            FreeCredentialsHandle(&self.handle)
            self.needs_free = 0

    @property
    def expiry(Credential self) -> int:
        return (<unsigned long long>self.raw_expiry.HighPart << 32) | self.raw_expiry.LowPart

cdef class AuthIdentity:

    cdef void *__c_value__(AuthIdentity self):
        return NULL

cdef class WinNTAuthIdentity(AuthIdentity):
    cdef SEC_WINNT_AUTH_IDENTITY_EXW raw
    cdef WideCharString username_raw
    cdef WideCharString domain_raw
    cdef WideCharString password_raw
    cdef WideCharString package_list_raw

    def __cinit__(
        WinNTAuthIdentity self,
        username: str | None = None,
        domain: str | None = None,
        password: str | None = None,
        *,
        flags: WinNTAuthFlags | int = 0,
        package_list: str | None = None,
    ) -> None:
        self.raw.Version = SEC_WINNT_AUTH_IDENTITY_VERSION
        self.raw.Length = <unsigned long>sizeof(SEC_WINNT_AUTH_IDENTITY_EXW)

        self._username = username
        self.username_raw = WideCharString(username)
        self.raw.User = <unsigned short*>self.username_raw.buffer
        self.raw.UserLength = <unsigned long>self.username_raw.length

        self._domain = domain
        self.domain_raw = WideCharString(domain)
        self.raw.Domain = <unsigned short*>self.domain_raw.buffer
        self.raw.DomainLength = <unsigned long>self.domain_raw.length

        self._password = password
        self.password_raw = WideCharString(password)
        self.raw.Password = <unsigned short*>self.password_raw.buffer
        self.raw.PasswordLength = <unsigned long>self.password_raw.length

        self._raw.Flags = int(flags) | _SEC_WINNT_AUTH_IDENTITY_UNICODE

        self._package_list = package_list
        self.package_list_raw = WideCharString(package_list)
        self.raw.PackageList = <unsigned short*>self.package_list_raw.buffer
        self.raw.PackageListLength = <unsigned long>self.package_list_raw.length

    cdef void *__c_value__(WinNTAuthIdentity self):
        return &self.raw

    def __repr__(WinNTAuthIdentity self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'username': self.username,
            'domain': self.domain,
            'password': self.password,
            'flags': self.flags,
            'package_list': self.package_list,
        }.items()]

        return f"WinNTAuthIdentity({', '.join(kwargs)})"

    def __str__(WinNTAuthIdentity self) -> str:
        username = self.username
        if self.domain:
            username = f"{self.domain}\\{username}"

        return username

    @property
    def username(self) -> str | None:
        return self._username

    @property
    def domain(self) -> str | None:
        return self._domain

    @property
    def password(self) -> str | None:
        return self._password

    @property
    def flags(self) -> WinNTAuthFlags:
        return WinNTAuthFlags(self._raw.Flags)

    @property
    def package_list(self) -> str | None:
        return self._package_list

def acquire_credentials_handle(
    str principal,
    str package not None,
    unsigned long credential_use,
    *,
    AuthIdentity auth_data = None,
) -> Credential:
    cdef Credential cred = Credential()
    cdef WideCharString principal_wstr = WideCharString(principal)
    cdef WideCharString package_wstr = WideCharString(package)
    cdef void *auth_data_buffer = NULL

    if auth_data is not None:
        auth_data_buffer = auth_data.__c_value__()

    with nogil:
        res = AcquireCredentialsHandleW(
            principal_wstr.buffer,
            package_wstr.buffer,
            credential_use,
            NULL,
            auth_data_buffer,
            NULL,
            NULL,
            &cred.handle,
            &cred.raw_expiry
        )

    if res != 0:
        PyErr_SetFromWindowsErr(res)

    cred.needs_free = 1

    return cred