# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from ._context_attributes import (
    SecPkgContext,
    SecPkgContextNames,
    SecPkgContextPackageInfo,
    SecPkgContextSessionKey,
    SecPkgContextSizes,
    query_context_attributes,
)
from ._credential import (
    AuthIdentity,
    Credential,
    CredentialUse,
    WinNTAuthFlags,
    WinNTAuthIdentity,
    acquire_credentials_handle,
)
from ._credential_attributes import (
    KdcProxySettingsFlags,
    SecPkgCred,
    SecPkgCredKdcProxySettings,
    set_credentials_attributes,
)
from ._message import (
    QopFlags,
    decrypt_message,
    encrypt_message,
    make_signature,
    verify_signature,
)
from ._ntstatus import NtStatus
from ._security_buffer import (
    SECBUFFER_VERSION,
    SecBuffer,
    SecBufferDesc,
    SecBufferFlags,
    SecBufferType,
    SecChannelBindings,
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
    "Credential",
    "CredentialUse",
    "InitializeContextResult",
    "InitiatorSecurityContext",
    "IscReq",
    "IscRet",
    "KdcProxySettingsFlags",
    "NtStatus",
    "QopFlags",
    "SecBuffer",
    "SecBufferDesc",
    "SecBufferFlags",
    "SecBufferType",
    "SecChannelBindings",
    "SecPkgContext",
    "SecPkgContextNames",
    "SecPkgContextPackageInfo",
    "SecPkgContextSessionKey",
    "SecPkgContextSizes",
    "SecPkgCred",
    "SecPkgCredKdcProxySettings",
    "SecPkgInfo",
    "SecurityPackageCapability",
    "SecurityContext",
    "TargetDataRep",
    "WinNTAuthFlags",
    "WinNTAuthIdentity",
    "accept_security_context",
    "acquire_credentials_handle",
    "complete_auth_token",
    "decrypt_message",
    "encrypt_message",
    "enumerate_security_packages",
    "initialize_security_context",
    "make_signature",
    "query_context_attributes",
    "set_credentials_attributes",
    "verify_signature",
]
