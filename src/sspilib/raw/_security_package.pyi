# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum

class SecurityPackageCapability(enum.IntFlag):
    """Security Package capability flags."""

    SECPKG_FLAG_INTEGRITY = ...
    """Supports the :meth:`make_signature` and :meth:`verify_signature` functions."""
    SECPKG_FLAG_PRIVACY = ...
    """Supports the :meth:`encrypt_message` and :meth:`decrypt_message` functions."""
    SECPKG_FLAG_TOKEN_ONLY = ...
    """Package is only interested in security-token porition of messages."""
    SECPKG_FLAG_DATAGRAM = ...
    """Supports datagram-style authentication."""
    SECPKG_FLAG_CONNECTION = ...
    """Supports connection-oriented style authentication."""
    SECPKG_FLAG_MULTI_REQUIRED = ...
    """Multiple legs are required for authentication."""
    SECPKG_FLAG_CLIENT_ONLY = ...
    """Server authentication support is not provided."""
    SECPKG_FLAG_EXTENDED_ERROR = ...
    """Supported extended error handling."""
    SECPKG_FLAG_IMPERSONATION = ...
    """Supports Windows impersonation in server contexts."""
    SECPKG_FLAG_ACCEPT_WIN32_NAME = ...
    """Understands Windows principal and target names."""
    SECPKG_FLAG_STREAM = ...
    """Supports stream semantics."""
    SECPKG_FLAG_NEGOTIABLE = ...
    """Can be used by the Negotiate security package."""
    SECPKG_FLAG_GSS_COMPATIBLE = ...
    """Supports GSS compatibility."""
    SECPKG_FLAG_LOGON = ...
    """Supports LsaLogonUser."""
    SECPKG_FLAG_ASCII_BUFFERS = ...
    """Token buffers are in ASCII character format."""
    SECPKG_FLAG_FRAGMENT = ...
    """Supports separating large tokens into smaller buffers."""
    SECPKG_FLAG_MUTUAL_AUTH = ...
    """Supports mutual authentication."""
    SECPKG_FLAG_DELEGATION = ...
    """Supports delegation."""
    SECPKG_FLAG_READONLY_WITH_CHECKSUM = ...
    """Supports using a checksum instead of in-place encryption with :meth:`encrypt_message`."""
    SECPKG_FLAG_RESTRICTED_TOKENS = ...
    """Supports callers with restricted tokens."""
    SECPKG_FLAG_NEGO_EXTENDER = ...
    """Extends the Negotiate security package."""
    SECPKG_FLAG_NEGOTIABLE2 = ...
    """Is negotiated by the nego extended package."""
    SECPKG_FLAG_APPCONTAINER_PASSTHROUGH = ...
    """Receieves all calls from app container apps."""
    SECPKG_FLAG_APPCONTAINER_CHECKS = ...
    """Receives calls from app containers apps for more specific scenarios."""
    SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED = ...
    """Is running with CredHandle Guard enabled."""
    SECPKG_FLAG_APPLY_LOOPBACK = ...
    """Supports reliable detection of loopback."""

@dataclasses.dataclass
class SecPkgInfo:
    """Security Package info returned by :meth:`enumerate_security_packages`."""

    capabilities: SecurityPackageCapability
    """Set of capabilities of the security package."""
    version: int
    """The version of the package."""
    rpcid: int
    """The DCE RPC identifier if appropriate."""
    max_token: int
    """The maximum size, in bytes, of the token."""
    name: str
    """The name of the security package."""
    comment: str
    """Additional information about the security package."""

def enumerate_security_packages() -> list[SecPkgInfo]:
    """Enumerates installed security packages.

    Enumerates the security packages that are available to the client.

    The ``name`` attribute is the security package name that can be used with
    :meth:`acquire_credentials_handle`.

    This wraps the `EnumerateSecurityPackages`_ Win32 function.

    Returns:
        list[SecPkgInfo]: The list of security packages.

    Raises:
        WindowsError: If the function failed.

    .. EnumerateSecurityPackages:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw
    """
