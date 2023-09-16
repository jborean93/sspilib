# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from ._credential import (
    AuthIdentity,
    CredentialUse,
    WinNTAuthIdentity,
    acquire_credentials_handle,
)
from ._ntstatus import NtStatus
from ._security_buffer import (
    SECBUFFER_VERSION,
    SecBuffer,
    SecBufferDesc,
    SecBufferFlags,
    SecBufferType,
    free_context_buffer,
)
from ._security_context import (
    AcceptContextResult,
    AcceptorSecurityContext,
    AscReq,
    AscRet,
    InitializeContextResult,
    InitiatorSecurityContext,
    IscReq,
    IscRet,
    SecurityContext,
    TargetDataRep,
    accept_security_context,
    complete_auth_token,
    initialize_security_context,
)
from ._security_package import (
    SecPkgInfo,
    SecurityPackageCapability,
    enumerate_security_packages,
)

__all__ = [
    "SECBUFFER_VERSION",
    "AcceptContextResult",
    "AcceptorSecurityContext",
    "AscReq",
    "AscRet",
    "AuthIdentity",
    "CredentialUse",
    "InitializeContextResult",
    "InitiatorSecurityContext",
    "IscReq",
    "IscRet",
    "NtStatus",
    "SecBuffer",
    "SecBufferDesc",
    "SecBufferFlags",
    "SecBufferType",
    "SecPkgInfo",
    "SecurityPackageCapability",
    "SecurityContext",
    "TargetDataRep",
    "WinNTAuthIdentity",
    "accept_security_context",
    "acquire_credentials_handle",
    "complete_auth_token",
    "enumerate_security_packages",
    "initialize_security_context",
    "free_context_buffer",
]
