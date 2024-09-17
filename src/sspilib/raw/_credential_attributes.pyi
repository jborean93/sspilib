# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from ._credential import CredHandle

class KdcProxySettingsFlags(enum.IntEnum):
    """Flags used for :class:`SecPkgCredKdcProxySettings`"""

    KDX_PROXY_SETTINGS_FLAGS_NONE = ...
    """No flags are set."""

    KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY = ...
    """
    Force the use of the proxy specified and do not attempt to talk to the KDC
    directly.
    """

class SecPkgCred:
    """Base class for credential attribute types."""

class SecPkgCredKdcProxySettings(SecPkgCred):
    """Kerberos proxy settings.

    Specifies the kerberos proxy settings for the credentials. The proxy_server
    is in the format of ``hostname:port:path`` where ``port:path`` can be
    omitted for the default of ``443:KdcProxy``.

    This wraps the `SecPkgCredentials_KdcProxySettingsW`_ Win32 structure.

    .. _SecPkgCredentials_KdcProxySettingsW:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcredentials_kdcproxysettingsw
    """

    def __init__(
        self,
        *,
        flags: int = 0,
        proxy_server: str | None = None,
    ) -> None: ...
    @property
    def version(self) -> int:
        """The version of the internal structure."""

    @property
    def flags(self) -> KdcProxySettingsFlags:
        """Flags for the Kerberos proxy settings."""

    @property
    def proxy_server(self) -> str | None:
        """The proxy server value."""

def set_credentials_attributes(
    context: CredHandle,
    attribute: SecPkgCred,
) -> None:
    """Sets the attributes of a credential.

    Sets the attributes of a credential, such as the name associated with the
    credential. The information is valid for any security context created with
    the specified credential. The credential can be created with
    :meth:`acquire_credentials_handle`.

    The following attributes have been implemented:

        :class:`SecPkgCredKdcProxySettings`

    This wraps the `SetCredentialsAttributesW`_ Win32 function.

    Args:
        credential: The credential to set the attribute on.
        attribute: The attribute to set.

    Raises:
        WindowsError: If the function failed.

    .. _SetCredentialsAttributesW:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesw
    """
