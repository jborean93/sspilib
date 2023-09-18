# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from ._security_context import SecurityContext

T = t.TypeVar("T", bound=SecPkgBuffer)

class SecPkgBuffer:
    """Base class for context attribute types."""

class SecPkgContextNames(SecPkgBuffer):
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

class SecPkgContextSessionKey(SecPkgBuffer):
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

class SecPkgContextSizes(SecPkgBuffer):
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
    context: SecurityContext,
    attribute: type[T],
) -> T:
    """Queries an attribute of a security context.

    Enables a transport application to query a security package for certain
    attributes of a security context.

    The attribute must be a type that is a subclass of :class:`SecPkgBuffer`.
    The instance is created, populated, and returned by this function.

    This wraps the `QueryContextAttributes`_ Win32 function.

    Args:
        context: The security context to query.
        attribute: The attribute type to query and return.

    Returns:
        The instance of the attribute type provided.

    .. _QueryContextAttributes:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general
    """
