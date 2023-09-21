# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing as t

from ._credential import CredHandle
from ._ntstatus import NtStatus
from ._security_buffer import SecBufferDesc

class TargetDataRep(enum.IntEnum):
    """The data representation format."""

    SECURITY_NATIVE_DREP = ...
    """The data is to be represented as the native endianess."""
    SECURITY_NETWORK_DREP = ...
    """The data is to be represented as network order or big endianess."""

class AscReq(enum.IntFlag):
    """Special context request flags.

    Special flags to request for an accept security context. These flags
    are specified in the :meth:`accept_security_context` under the
    ``context_req`` argument. The meaning and behaviour of each flag is
    controlled by the security package being used.
    """

    ASC_REQ_DELEGATE = ...
    """"The server is allowed to impersonate the client."""
    ASC_REQ_MUTUAL_AUTH = ...
    """"
    The client is required to supply a certificate to be used for client
    authentication.
    """
    ASC_REQ_REPLAY_DETECT = ...
    """Detetct replayed packets."""
    ASC_REQ_SEQUENCE_DETECT = ...
    """Detect messages received out of sequence."""
    ASC_REQ_CONFIDENTIALITY = ...
    """Encrypt and decrypt messages."""
    ASC_REQ_USE_SESSION_KEY = ...
    """A new session key must be negotiated."""
    ASC_REQ_SESSION_TICKET = ...
    ASC_REQ_ALLOCATE_MEMORY = ...
    """
    Digest and Schannel will allocate output buffers for you. When the buffers
    are deallocated they will free the memory allocated by SSPI.
    """
    ASC_REQ_USE_DCE_STYLE = ...
    """The caller expects a three-leg authentication transaction."""
    ASC_REQ_DATAGRAM = ...
    ASC_REQ_CONNECTION = ...
    """The security context will not handle formatting messages."""
    ASC_REQ_CALL_LEVEL = ...
    ASC_REQ_FRAGMENT_SUPPLIED = ...
    ASC_REQ_EXTENDED_ERROR = ...
    """When errors occur, the remote party will be notified."""
    ASC_REQ_STREAM = ...
    """Support a stream-oriented connection."""
    ASC_REQ_INTEGRITY = ...
    """Sign messages and verify signatures."""
    ASC_REQ_LICENSING = ...
    ASC_REQ_IDENTIFY = ...
    """
    When a server impersonates a context that has this flag set, the
    impersonation yields extremely limited access. Impersonation with IDENTITY
    set is used to verify the client's identity.
    """
    ASC_REQ_ALLOW_NULL_SESSION = ...
    ASC_REQ_ALLOW_NON_USER_LOGONS = ...
    ASC_REQ_ALLOW_CONTEXT_REPLAY = ...
    ASC_REQ_FRAGMENT_TO_FIT = ...
    ASC_REQ_NO_TOKEN = ...
    ASC_REQ_PROXY_BINDINGS = ...
    """
    Indicates that Digest requires channel binding. This value is mutually
    exclusive with ASC_REQ_ALLOW_MISSING_BINDINGS.
    """
    ASC_REQ_ALLOW_MISSING_BINDINGS = ...
    """
    Indicates that Digest does not require channel bindings for both inner and
    outer channels. This value is used for backward compatibility when support
    for endpoint channel binding is not known.
    """

class AscRet(enum.IntFlag):
    """Context attribute flags.

    Flags that indicate the attributes of an established context. Most flags
    correspond to the ``ASC_REQ_`` equivalents with the same name.
    """

    ASC_RET_DELEGATE = ...
    ASC_RET_MUTUAL_AUTH = ...
    ASC_RET_REPLAY_DETECT = ...
    ASC_RET_SEQUENCE_DETECT = ...
    ASC_RET_CONFIDENTIALITY = ...
    ASC_RET_USE_SESSION_KEY = ...
    ASC_RET_SESSION_TICKET = ...
    ASC_RET_ALLOCATED_MEMORY = ...
    ASC_RET_USED_DCE_STYLE = ...
    ASC_RET_DATAGRAM = ...
    ASC_RET_CONNECTION = ...
    ASC_RET_CALL_LEVEL = ...
    ASC_RET_THIRD_LEG_FAILED = ...
    ASC_RET_EXTENDED_ERROR = ...
    ASC_RET_STREAM = ...
    ASC_RET_INTEGRITY = ...
    ASC_RET_LICENSING = ...
    ASC_RET_IDENTIFY = ...
    ASC_RET_NULL_SESSION = ...
    ASC_RET_ALLOW_NON_USER_LOGONS = ...
    ASC_RET_ALLOW_CONTEXT_REPLAY = ...
    ASC_RET_FRAGMENT_ONLY = ...
    ASC_RET_NO_TOKEN = ...
    ASC_RET_NO_ADDITIONAL_TOKEN = ...

class IscReq(enum.IntFlag):
    """Special context request flags.

    Special flags to request for an initiated security context. These flags
    are specified in the :meth:`initialize_security_context` under the
    ``context_req`` argument. The meaning and behaviour of each flag is
    controlled by the security package being used.
    """

    ISC_REQ_DELEGATE = ...
    """
    The server can use the context to authenticate to other servers as the
    client. The `ISC_REQ_MUTUAL_AUTH` flag must be set for this to work. Valid
    for Kerberos. Ignore this flag for constrained delegation.
    """
    ISC_REQ_MUTUAL_AUTH = ...
    """
    The mutual authentication policy of the server will be satisified. This
    does not necessarily mean mutual authentication is performed, only that
    the authentication policy of the server is satisfied.
    """
    ISC_REQ_REPLAY_DETECT = ...
    """
    Detect replayed messages that have been encoded by using the
    :meth:`encrypt_message` or :meth:`make_signature` functions.
    """
    ISC_REQ_SEQUENCE_DETECT = ...
    """Detect messages received out of sequence."""
    ISC_REQ_CONFIDENTIALITY = ...
    """Encrypt messages by using :meth:`encrypt_message`."""
    ISC_REQ_USE_SESSION_KEY = ...
    """A new session key must be negotiated. Only supported by Kerberos."""
    ISC_REQ_PROMPT_FOR_CREDS = ...
    """
    If the client is an interactive user, the package must, if possible, prompt
    the user for the appropriate credentials"""
    ISC_REQ_USE_SUPPLIED_CREDS = ...
    """
    Schannel must not attempt to supply credentials for the client automatically.
    """
    ISC_REQ_ALLOCATE_MEMORY = ...
    """
    The security package allocated the output buffers for you. The memory is
    automatically freed when the SecBuffer is deallocated.
    """
    ISC_REQ_USE_DCE_STYLE = ...
    """The caller expects a three-leg authentication transaction."""
    ISC_REQ_DATAGRAM = ...
    """Datagram semantics must be used."""
    ISC_REQ_CONNECTION = ...
    """
    The security context will not handle formatting messages. This value is the
    default for Kerneros, Negotiate, and NTLM constrained delegation.
    """
    ISC_REQ_CALL_LEVEL = ...
    ISC_REQ_FRAGMENT_SUPPLIED = ...
    ISC_REQ_EXTENDED_ERROR = ...
    """When errors occur, the remote party will be notified."""
    ISC_REQ_STREAM = ...
    """Support a stream-oriented connection."""
    ISC_REQ_INTEGRITY = ...
    """
    Sign messages and verify signatures using the :meth:`make_signature` and
    :meth:`verify_signature` functions.
    """
    ISC_REQ_IDENTIFY = ...
    """
    When a server impersonates a context that has this flag set, that
    impersonation yields extremely limited access. Impersonation with IDENTITY
    set is used to verify the client's identity.
    """
    ISC_REQ_NULL_SESSION = ...
    ISC_REQ_MANUAL_CRED_VALIDATION = ...
    """Schannel must not authenticate the server automatically."""
    ISC_REQ_RESERVED1 = ...
    ISC_REQ_FRAGMENT_TO_FIT = ...
    ISC_REQ_FORWARD_CREDENTIALS = ...
    ISC_REQ_NO_INTEGRITY = ...
    """
    The ISC_REQ_INTEGRITY flag is ignored. This value is supported only tbe the
    Negotiate and kebreros constrained delegations.
    """
    ISC_REQ_USE_HTTP_STYLE = ...
    ISC_REQ_UNVERIFIED_TARGET_NAME = ...
    """
    The provided target name comes from an untrusted source. This controls some
    extra behaviour with Extended Protection.
    """
    ISC_REQ_CONFIDENTIALITY_ONLY = ...

class IscRet(enum.IntFlag):
    """Context attribute flags.

    Flags that indicate the attributes of an established context. Most flags
    correspond to the ``ISC_REQ_`` equivalents with the same name.
    """

    ISC_RET_DELEGATE = ...
    ISC_RET_MUTUAL_AUTH = ...
    ISC_RET_REPLAY_DETECT = ...
    ISC_RET_SEQUENCE_DETECT = ...
    ISC_RET_CONFIDENTIALITY = ...
    ISC_RET_USE_SESSION_KEY = ...
    ISC_RET_USED_COLLECTED_CREDS = ...
    ISC_RET_USED_SUPPLIED_CREDS = ...
    ISC_RET_ALLOCATED_MEMORY = ...
    ISC_RET_USED_DCE_STYLE = ...
    ISC_RET_DATAGRAM = ...
    ISC_RET_CONNECTION = ...
    ISC_RET_INTERMEDIATE_RETURN = ...
    ISC_RET_CALL_LEVEL = ...
    ISC_RET_EXTENDED_ERROR = ...
    ISC_RET_STREAM = ...
    ISC_RET_INTEGRITY = ...
    ISC_RET_IDENTIFY = ...
    ISC_RET_NULL_SESSION = ...
    ISC_RET_MANUAL_CRED_VALIDATION = ...
    ISC_RET_RESERVED1 = ...
    ISC_RET_FRAGMENT_ONLY = ...
    ISC_RET_FORWARD_CREDENTIALS = ...
    ISC_RET_USED_HTTP_STYLE = ...
    ISC_RET_NO_ADDITIONAL_TOKEN = ...
    ISC_RET_REAUTHENTICATION = ...
    ISC_RET_CONFIDENTIALITY_ONLY = ...

class CtxtHandle:
    """A security context.

    This contains the security context handle that was setup with either
    :meth:`accept_security_context` or :meth:`initialize_security_context`.
    Once no longer referenced, the handle will be freed internally, closing
    the security context.
    """

class AcceptContextResult(t.NamedTuple):
    """The accept security context result."""

    context: CtxtHandle
    """
    The generated context to use for subsequent operations on this context.
    This context should be passed as the `context` arg on any remaining calls
    to :meth:`accept_security_context`.
    """
    attributes: AscRet
    """
    A set of flags that indicate the attributes of the established context.
    Security-related attributes should only be checked until the status
    ``SEC_E_OK`` has been received. Non-security related attributes can be
    checked before the context is fully established.
    """
    expiry: int
    """The time at which the context expires as a FILETIME value."""
    status: NtStatus
    """The NtStatus code result of the operation."""

class InitializeContextResult(t.NamedTuple):
    """The initialize security context result."""

    context: CtxtHandle
    """
    The generated context to use for subsequent operations on this context.
    This context should be passed as the `context` arg on any remaining calls
    to :meth:`initialize_security_context`.
    """
    attributes: IscRet
    """
    A set of flags that indicate the attributes of the established context.
    Security-related attributes should only be checked until the status
    ``SEC_E_OK`` has been received. Non-security related attributes can be
    checked before the context is fully established.
    """
    expiry: int
    """The time at which the context expires as a FILETIME value."""
    status: NtStatus
    """The NtStatus code result of the operation."""

def accept_security_context(
    credential: CredHandle | None,
    context: CtxtHandle | None,
    input_buffers: SecBufferDesc | None,
    context_req: AscReq | int,
    target_data_rep: TargetDataRep | int,
    output_buffers: SecBufferDesc | None,
) -> AcceptContextResult:
    """Initiates the server side security context.

    This function initiates the server side, inbound security context from a
    credentials handle. It is used to build a security context between the
    application and a remote peer.

    The function should be called in a loop until a sufficient security
    context is established. The security tokens generated in the output_buffers
    should be exchanged with the peer and any tokens received from that peer
    should be placed in the input_buffers. The values that can be returned as
    the result values are:

        SEC_E_OK - the context was initialized
        SEC_I_CONTINUE_NEEDED - more input tokens are needed
        SEC_I_COMPLETE_NEEDED - context needs to be completed
        SEC_I_COMPLETE_AND_CONTINUE - more tokens and must be completed

    To complete a security context call :meth:`complete_auth_token`. Currently
    only the Digest security provider is known to require completion.

    The credential can be a credential generated by
    :meth:`acquire_credentials_handle` or ``None``. If ``None``, the current
    user context will be used. A credential can control what security provider
    is used for authentication so should be set in most circumstances.

    The context should be set to ``None`` on the first call and the returned
    context result on subsequent calls.

    The input buffers contains any input tokens, or other buffer types
    supported by the security package. It is typically set to the data received
    by the client. It may contain more buffer types like
    ``SECBUFFER_CHANNEL_BINDINGS``.

    The context req are a set of :class:`AscReq` flags for the context.
    The behaviour of these flags are dependent on the security provider being
    used.

    The target_data_rep specifies the data representation. Typically this is
    just set to ``SECURITY_NETWORK_DREP``.

    The output buffers contain the buffers which will store the output tokens
    generated by the security package. The buffers must be large enough to
    contain the data that could be generated by that buffer type or the
    context_req ``ASC_REQ_ALLOCATE_MEMORY`` is specified.

    This function wraps the `AcceptSecurityContext`_ Win32 function.

    Args:
        credential: Optional credential to use for this security exchange.
        context: Must be None on the first call and the returned security
            context on the next call(s)
        input_buffers: The buffers supplied as input to the package.
        context_req: Specify special request flags for the context.
        target_data_rep: Specifies the data representation, such as byte
            ordering, on the target.
        output_buffers: The buffers that will contain the output from the
            security package.

    Returns:
        AcceptorContextResult: Contains the security context, attributes,
        expiry, and NtStatus result from the call.

    Raises:
        WindowsError: If the function failed.

    .. _AcceptSecurityContext:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--general
    """

def complete_auth_token(
    context: CtxtHandle,
    token: SecBufferDesc,
) -> None:
    """Completes an authentication token.

    This function is used by protocols, such as DCE, that need to revise the
    security information after the transport application has updated some
    message parameters.

    This function is supported only by the Digest security provider and is used
    on the server side only.

    This function wraps the `CompleteAuthToken`_ Win32 function.

    Args:
        context: A handle of the context that needs to be completed.
        token: A SecBufferDesc that contains the token to be completed.

    Raises:
        WindowsError: If the function failed.

    .. _CompleteAuthToken:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-completeauthtoken
    """

def initialize_security_context(
    credential: CredHandle | None,
    context: CtxtHandle | None,
    target_name: str,
    context_req: IscReq | int,
    target_data_rep: TargetDataRep | int,
    input_buffers: SecBufferDesc | None,
    output_buffers: SecBufferDesc | None,
) -> InitializeContextResult:
    """Initiates the client side security context.

    This function initiates the client side, outbound security context from a
    credentials handle. It is used to build a security context between the
    application and a remote peer.

    The function should be called in a loop until a sufficient security
    context is established. The security tokens generated in the output_buffers
    should be exchanged with the peer and any tokens received from that peer
    should be placed in the input_buffers. The values that can be returned as
    the result values are:

        SEC_E_OK - the context was initialized
        SEC_I_CONTINUE_NEEDED - more input tokens are needed
        SEC_I_COMPLETE_NEEDED - context needs to be completed
        SEC_I_COMPLETE_AND_CONTINUE - more tokens and must be completed

    To complete a security context call :meth:`complete_auth_token`. Currently
    only the Digest security provider is known to require completion.

    The credential can be a credential generated by
    :meth:`acquire_credentials_handle` or ``None``. If ``None``, the current
    user context will be used. A credential can control what security provider
    is used for authentication so should be set in most circumstances.

    The context should be set to ``None`` on the first call and the returned
    context result on subsequent calls.

    The target name is set to a security provider specific format. For example
    with Kerberos, Negotiate, and NTLM it should be set to the Service
    Principal Name (SPN) or the target. For Schannel/TLS it should be set to
    the target hostname used for certificate name verification.

    The context req are a set of :class:`IscReq` flags for the context.
    The behaviour of these flags are dependent on the security provider being
    used.

    The target_data_rep specifies the data representation. Typically this is
    just set to ``SECURITY_NETWORK_DREP``.

    The input buffers contains any input tokens, or other buffer types
    supported by the security package. It is typically set to ``None` on the
    first call and contains the server response token on subsequent calls.
    Other buffers like ``SECBUFFER_CHANNEL_BINDINGS`` can be specified here
    dependent on the security provider used.

    The output buffers contain the buffers which will store the output tokens
    generated by the security package. The buffers must be large enough to
    contain the data that could be generated by that buffer type or the
    context_req ``ISC_REQ_ALLOCATE_MEMORY`` is specified.

    This function wraps the `InitializeSecurityContext`_ Win32 function.

    Args:
        credential: Optional credential to use for this security exchange.
        context: Must be None on the first call and the returned security
            context on the next call(s)
        target_name: The target of the context.
        context_req: Specify special request flags for the context.
        target_data_rep: Specifies the data representation, such as byte
            ordering, on the target.
        input_buffers: The buffers supplied as input to the package.
        output_buffers: The buffers that will contain the output from the
            security package.

    Returns:
        InitializeContextResult: Contains the security context, attributes,
        expiry, and NtStatus result from the call.

    Raises:
        WindowsError: If the function failed.

    .. _InitializeSecurityContext:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--general
    """
