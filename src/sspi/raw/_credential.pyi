# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing as t

class CredentialUse(enum.IntFlag):
    """CredHandle Usage Flags for :meth:`acquire_credentials_handle`."""

    SECPKG_CRED_INBOUND = ...
    """Validate an incoming server credential."""

    SECPKG_CRED_OUTBOUND = ...
    """Allow a local client credential to prepare an outgoing token."""

    SECPKG_CRED_BOTH = ...
    """Validate an incoming credential or use a local credential to prepare an outgoing token."""

    SECPKG_CRED_AUTOLOGON_RESTRICTED = ...
    """Do not use the default logon credentials or credentials from CredHandle Manager"""

    SECPKG_CRED_PROCESS_POLICY_ONLY = ...
    """Process server policy."""

class WinNTAuthFlags(enum.IntFlag):
    SEC_WINNT_AUTH_IDENTITY_ANSI = ...
    """Credentials are in ANSI form."""
    SEC_WINNT_AUTH_IDENTITY_UNICODE = ...
    """Credentials are in Unicode form."""
    SEC_WINNT_AUTH_IDENTITY_MARSHALLED = ...
    """All data is in one buffer."""
    SEC_WINNT_AUTH_IDENTITY_ONLY = ...
    """Used with Kerberos to specify the cred are for identity only."""
    SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN = ...
    SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER = ...

class CredHandle:
    """A credential handle.

    This contains the credential handle that was created with
    :meth:`acquire_credentials_handle`. Once no longer referenced, the handle
    will be freed internally, closing the credential handle.
    """

class AuthIdentity:
    """Base class for :meth:`acquire_credentials_handle` auth_data."""

class WinNTAuthIdentity(AuthIdentity):
    """Username and password identity information.

    This is an authentication data object that contains the username and
    password information for a user. It can be used with the ``auth_data``
    kwarg on :meth:`acquire_credentials_handle` to acquire a credential with
    an explicit username/password.

    If using the Netlogon form ``DOMAIN\\username``, the ``username`` arg is
    ``username`` and the ``domain`` arg is ``DOMAIN``. If using the UPN form
    ``username@DOMAIN.COM``, the ``username`` is that UPN value while ``domain``
    is None.

    The ``package_list`` kwarg can be used to restrict what security packages
    the ``Negotiate`` provider can use with this credential. For example to
    use the ``Negotiate`` provider but disable NTLM authentication the value
    ``!ntlm`` can be specified.

    The only supported flag is ``SEC_WINNT_AUTH_IDENTITY_ONLY``, setting any
    other value will have an unknown outcome.

    Args:
        username: The username.
        domain: The domain of the user.
        password: The user's password.
        flags: Custom flags associated with this identity.
        package_list: Comma separated list of names of security packages that
            are available to the Negotiate package.
    """

    def __init__(
        self,
        username: str | None = None,
        domain: str | None = None,
        password: str | None = None,
        *,
        flags: WinNTAuthFlags | int = 0,
        package_list: str | None = None,
    ) -> None: ...
    @property
    def username(self) -> str | None:
        """The identity username."""
    @property
    def domain(self) -> str | None:
        """The identity domain."""
    @property
    def password(self) -> str | None:
        """The identity password."""
    @property
    def flags(self) -> WinNTAuthFlags:
        """Custom flags associated with the identity."""
    @property
    def package_list(self) -> str | None:
        """A comma-separated list of security packages that are available to the Negotiate provider."""

class AcquireCredentialsResult(t.NamedTuple):
    """The acquire credentials handle result."""

    credential: CredHandle
    """
    The generated context to use for subsequent operations on this context.
    This context should be passed as the `context` arg on any remaining calls
    to :meth:`accept_security_context`.
    """
    expiry: int
    """The time at which the credential expires as a FILETIME value."""

def acquire_credentials_handle(
    principal: str | None,
    package: str,
    credential_use: CredentialUse | int,
    *,
    auth_data: AuthIdentity | None = None,
) -> AcquireCredentialsResult:
    """Acquires a handle to a credential.

    This function can be used to acquire a handle to a preexisting credential
    or to a new credential specified by this function. The credential can be
    used with functions like :meth:`initialize_sec_context` or
    :meth:`accept_sec_context` to perform the authentication steps.

    Currently the only authentication data value supported is
    :class:`WinNTAuthIdentity`.

    This wraps the `AcquireCredentialsHandle`_ Win32 function.

    Args:
        principal: Name of the principal whose credentials the handle will
            reference. The handling of this value is implemented in the
            security package requested.
        package: The security package name for which these credentials will be
            used.
        credential_use: Indicates how these credentials will be used.
        auth_data: Optional package specific authentication data.

    Returns:
        AcquireCredentialsResult: The acquired credential object and expiry.

    Raises:
        WindowsError: If the function failed.

    .. _AcquireCredentialsHandle:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general
    """

def _replace_cred_handle(
    src: CredHandle,
    dst: CredHandle,
) -> None:
    """Internal use only."""
