# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from ._security_context import CtxtHandle
from ._security_package import SecurityPackageCapability

T = t.TypeVar("T", bound=SecPkgContext)

class SecPkgContext:
    """Base class for context attribute types."""

class SecPkgContextNames(SecPkgContext):
    """Security Package Names

    The structure indicates the name of the user associated with a security
    context.

    This wraps the `SecPkgContext_NamesW`_ Win32 structure.

    .. _SecPkgContext_NamesW:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_namesw
    """

    @property
    def username(self) -> str:
        """The user represented by the context."""

class SecPkgContextPackageInfo(SecPkgContext):
    """Security Package Information

    The structure contains the package information associated with a security
    context.

    This wraps the `SecPkgContext_PackageInfoW`_ Win32 structure.

    .. _SecPkgContext_PackageInfoW:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_packageinfow
    """

    @property
    def capabilities(self) -> SecurityPackageCapability:
        """Set of capabilities of the security package."""

    @property
    def version(self) -> int:
        """The version of the package."""

    @property
    def rpcid(self) -> int:
        """The DCE RPC identifier if appropriate."""

    @property
    def max_token(self) -> int:
        """The maximum size, in bytes, of the token."""

    @property
    def name(self) -> str:
        """The name of the security package."""

    @property
    def comment(self) -> str:
        """Additional information about the security package."""

class SecPkgContextSessionKey(SecPkgContext):
    """Security Package session key.

    The structure contains information about the session key used for the
    security context.

    This wraps the `SecPkgContext_SessionKey`_ Win32 structure.

    .. _SecPkgContext_SessionKey:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sessionkey
    """

    @property
    def session_key(self) -> bytes:
        """The session key for the security context."""

class SecPkgContextSizes(SecPkgContext):
    """Security Package sizes.

    The structure indicates the sizes of important structures used in the
    message support functions. Use :meth:`query_context_attributes` to generate
    this instance.

    This wraps the `SecPkgContext_Sizes`_ Win32 structure.

    .. _SecPkgContextSizes:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sizes
    """

    @property
    def max_token(self) -> int:
        """Maximum security token sizes."""

    @property
    def max_signature(self) -> int:
        """Maximum signature size."""

    @property
    def block_size(self) -> int:
        """Preferred integral size of messages."""

    @property
    def security_trailer(self) -> int:
        """Size of the security trailer appended to messages."""

def query_context_attributes(
    context: CtxtHandle,
    attribute: type[T],
) -> T:
    """Queries an attribute of a security context.

    Enables a transport application to query a security package for certain
    attributes of a security context.

    The attribute must be a type that is a subclass of :class:`SecPkgContext`.
    The instance is created, populated, and returned by this function.

    The following attributes have been implemented:

        :class:`SecPkgContextNames`
        :class:`SecPkgContextPackageInfo`
        :class:`SecPkgContextSessionKey`
        :class:`SecPkgContextSizes`

    This wraps the `QueryContextAttributes`_ Win32 function.

    Args:
        context: The security context to query.
        attribute: The attribute type to query and return.

    Returns:
        The instance of the attribute type provided.

    Raises:
        WindowsError: If the function failed.

    .. _QueryContextAttributes:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general
    """
