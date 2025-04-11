# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import collections
import enum
import uuid

from libc.stdint cimport uint64_t
from libc.stdlib cimport calloc, free
from libc.string cimport memcpy

from ._text cimport WideCharString, wide_char_to_str
from ._win32_types cimport *


cdef extern from "python_sspi.h":
    unsigned int _SECPKG_CRED_INBOUND "SECPKG_CRED_INBOUND"
    unsigned int _SECPKG_CRED_OUTBOUND "SECPKG_CRED_OUTBOUND"
    unsigned int _SECPKG_CRED_BOTH "SECPKG_CRED_BOTH"
    unsigned int _SECPKG_CRED_AUTOLOGON_RESTRICTED "SECPKG_CRED_AUTOLOGON_RESTRICTED"
    unsigned int _SECPKG_CRED_PROCESS_POLICY_ONLY "SECPKG_CRED_PROCESS_POLICY_ONLY"

    unsigned int _SEC_WINNT_AUTH_IDENTITY_ANSI "SEC_WINNT_AUTH_IDENTITY_ANSI"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_UNICODE "SEC_WINNT_AUTH_IDENTITY_UNICODE"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_MARSHALLED "SEC_WINNT_AUTH_IDENTITY_MARSHALLED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_ONLY "SEC_WINNT_AUTH_IDENTITY_ONLY"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED "SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED "SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER "SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN "SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN"
    unsigned int _SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER "SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER"

    unsigned int SEC_WINNT_AUTH_IDENTITY_VERSION
    unsigned int SEC_WINNT_AUTH_IDENTITY_VERSION_2

    GUID _SEC_WINNT_AUTH_DATA_TYPE_PASSWORD "SEC_WINNT_AUTH_DATA_TYPE_PASSWORD"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_CERT "SEC_WINNT_AUTH_DATA_TYPE_CERT"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_CREDMAN_CERT "SEC_WINNT_AUTH_DATA_TYPE_CREDMAN_CERT"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_NGC "SEC_WINNT_AUTH_DATA_TYPE_NGC"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_FIDO "SEC_WINNT_AUTH_DATA_TYPE_FIDO"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_KEYTAB "SEC_WINNT_AUTH_DATA_TYPE_KEYTAB"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_DELEGATION_TOKEN "SEC_WINNT_AUTH_DATA_TYPE_DELEGATION_TOKEN"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA "SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA"
    GUID _SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS "SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS"

    cdef struct _SEC_WINNT_AUTH_IDENTITY_EXW:
        unsigned int Version;
        unsigned int Length;
        unsigned short *User;
        unsigned int UserLength;
        unsigned short *Domain;
        unsigned int DomainLength;
        unsigned short *Password;
        unsigned int PasswordLength;
        unsigned int Flags;
        unsigned short *PackageList;
        unsigned int PackageListLength;
    ctypedef _SEC_WINNT_AUTH_IDENTITY_EXW SEC_WINNT_AUTH_IDENTITY_EXW
    ctypedef SEC_WINNT_AUTH_IDENTITY_EXW *PSEC_WINNT_AUTH_IDENTITY_EXW

    cdef struct _SEC_WINNT_AUTH_IDENTITY_EX2:
        unsigned int Version
        unsigned short cbHeaderLength
        unsigned int cbStructureLength
        unsigned int UserOffset
        unsigned short UserLength
        unsigned int DomainOffset
        unsigned short DomainLength
        unsigned int PackedCredentialsOffset
        unsigned short PackedCredentialsLength
        unsigned int Flags
        unsigned int PackageListOffset
        unsigned int PackageListLength
    ctypedef _SEC_WINNT_AUTH_IDENTITY_EX2 SEC_WINNT_AUTH_IDENTITY_EX2
    ctypedef SEC_WINNT_AUTH_IDENTITY_EX2 *PSEC_WINNT_AUTH_IDENTITY_EX2

    cdef struct _SEC_WINNT_AUTH_BYTE_VECTOR:
        unsigned long ByteArrayOffset
        unsigned short ByteArrayLength
    ctypedef _SEC_WINNT_AUTH_BYTE_VECTOR SEC_WINNT_AUTH_BYTE_VECTOR
    ctypedef SEC_WINNT_AUTH_BYTE_VECTOR *PSEC_WINNT_AUTH_BYTE_VECTOR

    cdef struct _SEC_WINNT_AUTH_DATA:
        GUID CredType
        SEC_WINNT_AUTH_BYTE_VECTOR CredData
    ctypedef _SEC_WINNT_AUTH_DATA SEC_WINNT_AUTH_DATA
    ctypedef SEC_WINNT_AUTH_DATA *PSEC_WINNT_AUTH_DATA

    cdef struct _SEC_WINNT_AUTH_PACKED_CREDENTIALS:
        unsigned short cbHeaderLength
        unsigned short cbStructureLength
        SEC_WINNT_AUTH_DATA AuthData
    ctypedef _SEC_WINNT_AUTH_PACKED_CREDENTIALS SEC_WINNT_AUTH_PACKED_CREDENTIALS
    ctypedef SEC_WINNT_AUTH_PACKED_CREDENTIALS *PSEC_WINNT_AUTH_PACKED_CREDENTIALS

    ctypedef void (*SEC_GET_KEY_FN)(
        void *Arg,
        void *Principal,
        unsigned int KeyVer,
        void **Key,
        SECURITY_STATUS *Status,
    )

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew
    SECURITY_STATUS AcquireCredentialsHandleW(
        LPWSTR         pPrincipal,
        LPWSTR         pPackage,
        unsigned int  fCredentialUse,
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


cdef _convert_guid_to_uuid(GUID guid):
    return uuid.UUID(fields=(
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        (
            <uint64_t>guid.Data4[2] << 40 |
            <uint64_t>guid.Data4[3] << 32 |
            <uint64_t>guid.Data4[4] << 24 |
            <uint64_t>guid.Data4[5] << 16 |
            <uint64_t>guid.Data4[6] << 8 |
            guid.Data4[7]
        )
    ))

class CredentialUse(enum.IntFlag):
    SECPKG_CRED_INBOUND = _SECPKG_CRED_INBOUND
    SECPKG_CRED_OUTBOUND = _SECPKG_CRED_OUTBOUND
    SECPKG_CRED_BOTH = _SECPKG_CRED_BOTH
    SECPKG_CRED_AUTOLOGON_RESTRICTED = _SECPKG_CRED_AUTOLOGON_RESTRICTED
    SECPKG_CRED_PROCESS_POLICY_ONLY = _SECPKG_CRED_PROCESS_POLICY_ONLY

class WinNTAuthCredentialType:
    SEC_WINNT_AUTH_DATA_TYPE_PASSWORD = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_PASSWORD)
    SEC_WINNT_AUTH_DATA_TYPE_CERT = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_CERT)
    SEC_WINNT_AUTH_DATA_TYPE_CREDMAN_CERT = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_CREDMAN_CERT)
    SEC_WINNT_AUTH_DATA_TYPE_NGC = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_NGC)
    SEC_WINNT_AUTH_DATA_TYPE_FIDO = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_FIDO)
    SEC_WINNT_AUTH_DATA_TYPE_KEYTAB = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_KEYTAB)
    SEC_WINNT_AUTH_DATA_TYPE_DELEGATION_TOKEN = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_DELEGATION_TOKEN)
    SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA)
    SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS = _convert_guid_to_uuid(_SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS)

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

cdef class CredHandle:
    # cdef _CredHandle raw
    # cdef int needs_free

    def __dealloc__(CredHandle self):
        if self.needs_free:
            FreeCredentialsHandle(&self.raw)
            self.needs_free = 0

cdef class AuthIdentity:

    cdef void *__c_value__(AuthIdentity self):
        return NULL

cdef class WinNTAuthIdentity(AuthIdentity):
    cdef SEC_WINNT_AUTH_IDENTITY_EXW raw
    cdef WideCharString username_wchar
    cdef WideCharString domain_wchar
    cdef WideCharString password_wchar
    cdef WideCharString package_list_wchar

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
        self.raw.Length = <unsigned int>sizeof(SEC_WINNT_AUTH_IDENTITY_EXW)

        self.username_wchar = WideCharString(username)
        self.raw.User = <unsigned short*>self.username_wchar.raw
        self.raw.UserLength = <unsigned int>self.username_wchar.length

        self.domain_wchar = WideCharString(domain)
        self.raw.Domain = <unsigned short*>self.domain_wchar.raw
        self.raw.DomainLength = <unsigned int>self.domain_wchar.length

        self.password_wchar = WideCharString(password)
        self.raw.Password = <unsigned short*>self.password_wchar.raw
        self.raw.PasswordLength = <unsigned int>self.password_wchar.length

        self.raw.Flags = int(flags) | _SEC_WINNT_AUTH_IDENTITY_UNICODE

        self.package_list_wchar = WideCharString(package_list)
        self.raw.PackageList = <unsigned short*>self.package_list_wchar.raw
        self.raw.PackageListLength = <unsigned int>self.package_list_wchar.length

    cdef void *__c_value__(WinNTAuthIdentity self):
        return &self.raw

    def __repr__(WinNTAuthIdentity self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'username': repr(self.username),
            'domain': repr(self.domain),
            'password': repr(self.password),
            'flags': self.flags,
            'package_list': repr(self.package_list),
        }.items()]

        return f"WinNTAuthIdentity({', '.join(kwargs)})"

    def __str__(WinNTAuthIdentity self) -> str:
        username = self.username
        if self.domain:
            username = f"{self.domain}\\{username}"

        return username

    @property
    def username(self) -> str | None:
        return wide_char_to_str(<LPWSTR>self.raw.User, self.raw.UserLength)

    @property
    def domain(self) -> str | None:
        return wide_char_to_str(<LPWSTR>self.raw.Domain, self.raw.DomainLength)

    @property
    def password(self) -> str | None:
        return wide_char_to_str(<LPWSTR>self.raw.Password, self.raw.PasswordLength)

    @property
    def flags(self) -> WinNTAuthFlags:
        return WinNTAuthFlags(self.raw.Flags)

    @property
    def package_list(self) -> str | None:
        return wide_char_to_str(<LPWSTR>self.raw.PackageList, self.raw.PackageListLength)

cdef class WinNTAuthIdentityPackedCredential(AuthIdentity):
    cdef PSEC_WINNT_AUTH_IDENTITY_EX2 raw

    def __cinit__(
        WinNTAuthIdentityPackedCredential self,
        credential_type: uuid.UUID,
        const unsigned char[:] credential not None,
        *,
        username: str | None = None,
        domain: str | None = None,
        flags: WinNTAuthFlags | int = 0,
        package_list: str | None = None,
    ) -> None:
        cdef const unsigned char[:] username_view = None
        username_bytes = None
        cdef unsigned int username_len = 0
        if username:
            username_bytes = username.encode("utf-16-le")
            username_len = <unsigned int>len(username_bytes)
            username_view = <const unsigned char[:username_len]><unsigned char*>username_bytes

        cdef const unsigned char[:] domain_view = None
        cdef bytes domain_bytes = None
        cdef unsigned int domain_len = 0
        if domain:
            domain_bytes = domain.encode("utf-16-le")
            domain_len = <unsigned int>len(domain_bytes)
            domain_view = <const unsigned char[:domain_len]><unsigned char*>domain_bytes

        cdef const unsigned char[:] package_list_view = None
        cdef bytes package_list_bytes = None
        cdef unsigned int package_list_len = 0
        if package_list:
            package_list_bytes = package_list.encode("utf-16-le")
            package_list_len = <unsigned int>len(package_list_bytes)
            package_list_view = <const unsigned char[:package_list_len]><unsigned char*>package_list_bytes

        cdef unsigned int packed_cred_len = <unsigned short>len(credential)
        cdef unsigned int raw_length = sizeof(SEC_WINNT_AUTH_IDENTITY_EX2) + \
            sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS) + \
            packed_cred_len + \
            username_len + \
            domain_len + \
            package_list_len
        self.raw = <PSEC_WINNT_AUTH_IDENTITY_EX2>calloc(raw_length, 1)
        if not self.raw:
            raise MemoryError("Cannot calloc SEC_WINNT_AUTH_IDENTITY_EX2 buffer")

        cdef unsigned char[:] raw_buffer = <unsigned char[:raw_length]><unsigned char*>self.raw
        cdef int current_offset = sizeof(SEC_WINNT_AUTH_IDENTITY_EX2)

        self.raw.Version = SEC_WINNT_AUTH_IDENTITY_VERSION_2
        self.raw.cbHeaderLength = sizeof(SEC_WINNT_AUTH_IDENTITY_EX2)
        self.raw.cbStructureLength = raw_length

        if username_len:
            self.raw.UserOffset = current_offset
            self.raw.UserLength = username_len
            raw_buffer[current_offset:current_offset + username_len] = username_view
            current_offset += username_len

        if domain:
            self.raw.DomainOffset = current_offset
            self.raw.DomainLength = domain_len
            raw_buffer[current_offset:current_offset + domain_len] = domain_view
            current_offset += domain_len

        self.raw.PackedCredentialsOffset = current_offset
        self.raw.PackedCredentialsLength = <unsigned short>sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS) + packed_cred_len

        cdef PSEC_WINNT_AUTH_PACKED_CREDENTIALS packed_credential = <PSEC_WINNT_AUTH_PACKED_CREDENTIALS>&(raw_buffer[current_offset])
        packed_credential.cbHeaderLength = sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS)
        packed_credential.cbStructureLength = self.raw.PackedCredentialsLength

        cdef const unsigned char* credential_type_buffer = <const unsigned char*>credential_type.bytes
        credential_type_fields = credential_type.fields
        packed_credential.AuthData.CredType.Data1 = credential_type_fields[0]
        packed_credential.AuthData.CredType.Data2 = credential_type_fields[1]
        packed_credential.AuthData.CredType.Data3 = credential_type_fields[2]
        memcpy(packed_credential.AuthData.CredType.Data4, &credential_type_buffer[8], 8)

        packed_credential.AuthData.CredData.ByteArrayOffset = packed_credential.cbHeaderLength
        packed_credential.AuthData.CredData.ByteArrayLength = packed_cred_len
        memcpy(&raw_buffer[current_offset + packed_credential.cbHeaderLength], <void*>&credential[0], packed_cred_len)
        current_offset += self.raw.PackedCredentialsLength

        self.raw.Flags = int(flags) | _SEC_WINNT_AUTH_IDENTITY_UNICODE

        if package_list:
            self.raw.PackageListOffset = current_offset
            self.raw.PackageListLength = package_list_len
            raw_buffer[current_offset:current_offset + package_list_len] = package_list_view

    def __dealloc__(WinNTAuthIdentityPackedCredential self):
        if self.raw:
            free(self.raw)
            self.raw = NULL

    cdef void *__c_value__(WinNTAuthIdentityPackedCredential self):
        return self.raw

    def __repr__(WinNTAuthIdentityPackedCredential self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'credential_type': repr(self.credential_type),
            'credential': repr(self.credential),
            'username': repr(self.username),
            'domain': repr(self.domain),
            'flags': self.flags,
            'package_list': repr(self.package_list),
        }.items()]

        return f"WinNTAuthIdentityPackedCredential({', '.join(kwargs)})"

    def __str__(WinNTAuthIdentity self) -> str:
        value = f"WinNTAuthIdentityPackedCredential {self.credential_type}"

        username = self.username
        if username:
            domain = self.domain
            if domain:
                username = f"{domain}\\{username}"
            value += f" for {username}"

        return value

    @property
    def credential_type(self) -> uuid.UUID:
        cdef PSEC_WINNT_AUTH_PACKED_CREDENTIALS cred = self._get_packed_cred()

        return _convert_guid_to_uuid(cred.AuthData.CredType)

    @property
    def credential(self) -> bytes:
        cdef PSEC_WINNT_AUTH_PACKED_CREDENTIALS cred = self._get_packed_cred()
        cdef char* cred_data = (<char*>cred) + cred.AuthData.CredData.ByteArrayOffset

        return cred_data[:cred.AuthData.CredData.ByteArrayLength]

    @property
    def username(self) -> str | None:
        return self._get_string_from_offset_length(
            self.raw.UserOffset,
            self.raw.UserLength,
        )

    @property
    def domain(self) -> str | None:
        return self._get_string_from_offset_length(
            self.raw.DomainOffset,
            self.raw.DomainLength,
        )

    @property
    def flags(self) -> WinNTAuthFlags:
        return WinNTAuthFlags(self.raw.Flags)

    @property
    def package_list(self) -> str | None:
        return self._get_string_from_offset_length(
            self.raw.PackageListOffset,
            self.raw.PackageListLength,
        )

    cdef PSEC_WINNT_AUTH_PACKED_CREDENTIALS _get_packed_cred(WinNTAuthIdentityPackedCredential self):
        if not self.raw or self.raw.PackedCredentialsOffset == 0 or self.raw.PackedCredentialsLength == 0:
            raise ValueError("buffer is unset or does not contain any packed credentials.")

        cdef int offset = self.raw.PackedCredentialsOffset
        return <PSEC_WINNT_AUTH_PACKED_CREDENTIALS>(<char*>self.raw + offset)

    cdef str _get_string_from_offset_length(
        WinNTAuthIdentityPackedCredential self,
        unsigned int offset,
        unsigned short length,
    ):
        cdef LPWSTR ptr = NULL
        if offset:
            ptr = <LPWSTR>(<unsigned char*>self.raw + offset)

        return wide_char_to_str(ptr, length // 2)


AcquireCredentialsResult = collections.namedtuple(
    'AcquireCredentialsResult',
    ['credential', 'expiry'],
)

def acquire_credentials_handle(
    str principal,
    str package not None,
    unsigned int credential_use,
    *,
    AuthIdentity auth_data = None,
) -> AcquireCredentialsResult:
    cdef CredHandle cred = CredHandle()
    cdef WideCharString principal_wstr = WideCharString(principal)
    cdef WideCharString package_wstr = WideCharString(package)
    cdef void *auth_data_buffer = NULL
    cdef TimeStamp raw_expiry

    if auth_data is not None:
        auth_data_buffer = auth_data.__c_value__()

    with nogil:
        res = AcquireCredentialsHandleW(
            principal_wstr.raw,
            package_wstr.raw,
            credential_use,
            NULL,
            auth_data_buffer,
            NULL,
            NULL,
            &cred.raw,
            &raw_expiry
        )

    if res != 0:
        PyErr_SetFromWindowsErr(res)

    cred.needs_free = 1

    return AcquireCredentialsResult(
        credential=cred,
        expiry=(<uint64_t>raw_expiry.HighPart << 32) | raw_expiry.LowPart,
    )

def _replace_cred_handle(
    CredHandle src not None,
    CredHandle dst not None,
) -> None:
    # This is only used by sspilib._credential.py to store the cred state in
    # itself.
    dst.raw = src.raw
    dst.needs_free = src.needs_free
    src.needs_free = 0
