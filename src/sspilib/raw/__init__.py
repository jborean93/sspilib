# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import sys

from ._context_attributes import (
    SecPkgContext,
    SecPkgContextNames,
    SecPkgContextPackageInfo,
    SecPkgContextSessionKey,
    SecPkgContextSizes,
    query_context_attributes,
)
from ._credential import (
    AcquireCredentialsResult,
    AuthIdentity,
    CredentialUse,
    CredHandle,
    WinNTAuthCredentialType,
    WinNTAuthFlags,
    WinNTAuthIdentity,
    WinNTAuthIdentityPackedCredential,
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
    AscReq,
    AscRet,
    CtxtHandle,
    InitializeContextResult,
    IscReq,
    IscRet,
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

if sys.platform == "win32":
    WindowsError = WindowsError
else:
    from ._winerror import WindowsError

__all__ = [
    "SECBUFFER_VERSION",
    "AcceptContextResult",
    "AscReq",
    "AscRet",
    "AcquireCredentialsResult",
    "AuthIdentity",
    "CredentialUse",
    "CredHandle",
    "CtxtHandle",
    "InitializeContextResult",
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
    "TargetDataRep",
    "WindowsError",
    "WinNTAuthCredentialType",
    "WinNTAuthFlags",
    "WinNTAuthIdentity",
    "WinNTAuthIdentityPackedCredential",
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
