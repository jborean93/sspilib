# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import abc
import datetime
import typing as t

import sspilib.raw as raw

from ._filetime import filetime_to_datetime


class UnwrapResult(t.NamedTuple):
    data: bytes
    qop: int


class SecurityContext(raw.CtxtHandle, metaclass=abc.ABCMeta):
    """Base class for a SecurityContext."""

    def __init__(
        self,
        credential: raw.CredHandle,
        channel_bindings: raw.SecChannelBindings | None = None,
    ) -> None:
        self._complete = False
        self._credential = credential
        self._channel_bindings = channel_bindings
        self._expiry = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
        self._sizes = raw.SecPkgContextSizes()
        self.__seq_no = 0

    @property
    def expiry(self) -> datetime.datetime:
        """The time when this security context expires."""
        return self._expiry

    @property
    def complete(self) -> bool:
        """Whether this context has been authenticated and ready to use for message operations."""
        return self._complete

    @property
    def _seq_no(self) -> int:
        seq_no = self.__seq_no
        self.__seq_no += 1
        return seq_no

    def step(
        self,
        in_token: bytes | bytearray | memoryview | None = None,
    ) -> bytes:
        """Perform an authentication step.

        Performs and authentication step to authenticate the context. The
        in_token is the token received from the peer to use for the
        authentication step. The first step for the client typically has no
        in_token as it generates the first one.

        This method should be called until the context has been marked as
        complete.

        If the in_token is a bytearray or memoryview that is writable, SSPI
        can potentially change the bytes in the buffer. To avoid this provide
        a byte string or a readonly memoryview.

        Args:
            in_token: The input token to use for the authentication step.

        Returns:
            bytes: The token to send to the peer for it to use as the next
            step. This will be an empty byte string if no more tokens are
            available to send.

        Raises:
            WindowsError: If the authentication step failed the WindowsError
            contains more information around the failure.
        """
        sec_buffers = []
        if in_token:
            sec_buffers.append(
                self._get_secbuffer_data(in_token, raw.SecBufferType.SECBUFFER_TOKEN),
            )

        if self._channel_bindings:
            sec_buffers.append(self._channel_bindings.dangerous_get_sec_buffer())

        input_buffers = None
        if sec_buffers:
            input_buffers = raw.SecBufferDesc(sec_buffers)

        output_buffers = raw.SecBufferDesc(
            [
                raw.SecBuffer(None, raw.SecBufferType.SECBUFFER_TOKEN),
            ]
        )
        status, expiry = self._step_internal(input_buffers, output_buffers)

        if status == raw.NtStatus.SEC_E_OK:
            self._complete = True
            self._sizes = raw.query_context_attributes(self, raw.SecPkgContextSizes)

        self._expiry = filetime_to_datetime(expiry)

        return output_buffers[0].data

    def wrap(
        self,
        data: bytes | bytearray | memoryview,
        encrypt: bool = True,
    ) -> bytes:
        """Wraps the data provided.

        This method is used to wrap the data in order to provide confidentially
        and integrity to the message. This method is designed to create a
        wrapped result that can be used by the :meth:`unwrap` function as well
        as GSSAPI's ``gss_unwrap`` function.

        If the provided data was a bytearray or a writable memoryview SSPI can
        mutate the data during the wrapping operation. If this is not desired
        then provide a byte string or readonly memoryview.

        This function defaults to encrypting the data. Set ``encrypt=False`` if
        you wish to generate a signature or use the :meth:`sign` method. It is
        up to the security provider that was negotiated in the authentication
        stage to honour the encryption request.

        If a more complex set of buffers is needed to wrap the data, use the
        :meth:`sspilib.raw.encrypt_message` function with this context.

        Args:
            data: The data to wrap.
            encrypt: Whether to encrypt the data or just sign it.

        Returns:
            bytes: The wrapped data.

        Raises:
            WindowsError: Contains the error information if the wrap failed.
        """
        token_data = bytearray(self._sizes.security_trailer)
        padding_data = bytearray(self._sizes.block_size)
        buffer = raw.SecBufferDesc(
            [
                raw.SecBuffer(token_data, raw.SecBufferType.SECBUFFER_TOKEN),
                self._get_secbuffer_data(data),
                raw.SecBuffer(padding_data, raw.SecBufferType.SECBUFFER_PADDING),
            ],
        )

        raw.encrypt_message(
            context=self,
            qop=0 if encrypt else raw.QopFlags.SECQOP_WRAP_NO_ENCRYPT,
            message=buffer,
            seq_no=self._seq_no,
        )

        return buffer[0].data + buffer[1].data + buffer[2].data

    def unwrap(
        self,
        data: bytes | bytearray | memoryview,
    ) -> UnwrapResult:
        """Unwraps the data provided.

        This method is used to unwrap the data provided to verify its integrity
        as well as decrypt the value. This method is designed to be able to
        unwrap a result from :meth:`wrap` as well as GSSAPI's ``gss_wrap``
        function.

        If the provided data was a bytearray or a writable memoryview SSPI can
        mutate the data during the unwrapping operation. If this is not desired
        then provide a byte string or readonly memoryview.

        If a more complex set of buffers is needed to unwrap the data, use the
        :meth:`sspilib.raw.decrypt_message` function with this context.

        Args:
            data: The data to unwrap.

        Returns:
            UnwrapResult: A tuple containing the unwrapped data and QoP value
            returned by the security provider for this operation.

        Raises:
            WindowsError: Contains the error information if the unwrap failed.
        """
        buffer = raw.SecBufferDesc(
            [
                self._get_secbuffer_data(data, raw.SecBufferType.SECBUFFER_STREAM),
                raw.SecBuffer(None, raw.SecBufferType.SECBUFFER_DATA),
            ]
        )
        qop = raw.decrypt_message(
            context=self,
            message=buffer,
            seq_no=self._seq_no,
        )

        return UnwrapResult(
            data=buffer[1].data,
            qop=qop,
        )

    def sign(
        self,
        data: bytes | bytearray | memoryview,
    ) -> bytes:
        """Signs the data provided.

        This method is used to sign the data in order to provide integrity to
        the message.

        If the provided data was a bytearray or a writable memoryview SSPI can
        mutate the data during the signing operation. If this is not desired
        then provide a byte string or readonly memoryview.

        If a more complex set of buffers is needed to sign the data, use the
        :meth:`sspilib.raw.make_signature` function with this context.

        Args:
            data: The data to sign.

        Returns:
            bytes: The signature for the data provided.

        Raises:
            WindowsError: Contains the error information if the signature
            operation failed.
        """
        in_token = bytearray(self._sizes.max_signature)
        buffer = raw.SecBufferDesc(
            [
                self._get_secbuffer_data(data),
                raw.SecBuffer(in_token, raw.SecBufferType.SECBUFFER_TOKEN),
            ]
        )

        raw.make_signature(
            context=self,
            qop=0,
            message=buffer,
            seq_no=self._seq_no,
        )

        return buffer[1].data

    def verify(
        self,
        data: bytes | bytearray | memoryview,
        mic: bytes | bytearray | memoryview,
    ) -> int:
        """Verifies the data provided.

        This method is used to verify a signature to ensure the data has not
        been modified.

        If the provided data was a bytearray or a writable memoryview SSPI can
        mutate the data during the unwrapping operation. If this is not desired
        then provide a byte string or readonly memoryview.

        If a more complex set of buffers is needed to unwrap the data, use the
        :meth:`sspilib.raw.verify_signature` function with this context.

        Args:
            data: The data to verify.
            mic: The signature to verify with

        Returns:
            int: The QoP value that was applied to the signature.

        Raises:
            WindowsError: Contains the error information if the verify
            operation failed.
        """
        buffer = raw.SecBufferDesc(
            [
                self._get_secbuffer_data(data),
                self._get_secbuffer_data(mic, raw.SecBufferType.SECBUFFER_TOKEN),
            ]
        )

        return raw.verify_signature(
            context=self,
            message=buffer,
            seq_no=self._seq_no,
        )

    @abc.abstractmethod
    def _step_internal(
        self,
        input_buffers: raw.SecBufferDesc | None,
        output_buffers: raw.SecBufferDesc | None,
    ) -> tuple[int, int]: ...

    def _get_secbuffer_data(
        self,
        data: bytes | bytearray | memoryview,
        buffer_type: raw.SecBufferType = raw.SecBufferType.SECBUFFER_DATA,
    ) -> raw.SecBuffer:
        buffer: bytearray | memoryview
        if isinstance(data, bytes) or (isinstance(data, memoryview) and data.readonly):
            buffer = bytearray(data)
        else:
            buffer = data

        return raw.SecBuffer(buffer, buffer_type)


class ClientSecurityContext(SecurityContext):
    """A client security context.

    This represents an SSPI security context that can be used for client side
    authentication. This class is designed to be a high level overlay on top of
    the :class:`sspilib.raw.CtxtHandle` class. it can be used directly with
    any low level API in the ``sspilib.raw`` namespace that requires a context
    handle instance in case the low level interface doesn't expose the methods
    needed.

    The client must specify a credential which stores the credential to use for
    authentication as well as extra information that controls how the
    security protocol will perform the authentication steps.

    The client must specify a target_name which is typically the Service
    Principal Name (SPN) of the service. It might be a different value
    depending on the security protocol used.

    By default the flags are set to request mutual auth, replay detection,
    sequence detection, confidentiality, and integrity if no flags are
    specified. Custom flags can be requested but it will overwrite the default
    set.

    Optional channel bindings can be specified which is used to tie the
    security context with an outer channel.

    Properties like ``expiry`` and ``attributes`` won't be populated until the
    context has been negotiated and is complete.

    Args:
        credential: A credential to use for authentication.
        target_name: The target service's name, typically the SPN.
        flags: Custom ISC REQ flags to use.
        channel_bindings: Optional channel bindings to tie the context to.
    """

    def __init__(
        self,
        credential: raw.CredHandle,
        target_name: str,
        flags: raw.IscReq | int | None = None,
        *,
        channel_bindings: raw.SecChannelBindings | None = None,
    ) -> None:
        super().__init__(credential=credential, channel_bindings=channel_bindings)
        self._target_name = target_name
        self._flags = (
            flags
            if flags is not None
            else (
                raw.IscReq.ISC_REQ_MUTUAL_AUTH
                | raw.IscReq.ISC_REQ_REPLAY_DETECT
                | raw.IscReq.ISC_REQ_SEQUENCE_DETECT
                | raw.IscReq.ISC_REQ_CONFIDENTIALITY
                | raw.IscReq.ISC_REQ_INTEGRITY
            )
        )
        self._attributes: raw.IscRet = raw.IscRet(0)

    @property
    def attributes(self) -> raw.IscRet:
        """Attributes of the current security context."""
        return self._attributes

    def _step_internal(
        self,
        input_buffers: raw.SecBufferDesc | None,
        output_buffers: raw.SecBufferDesc | None,
    ) -> tuple[int, int]:
        result = raw.initialize_security_context(
            credential=self._credential,
            context=self,
            target_name=self._target_name,
            context_req=self._flags | raw.IscReq.ISC_REQ_ALLOCATE_MEMORY,
            target_data_rep=raw.TargetDataRep.SECURITY_NATIVE_DREP,
            input_buffers=input_buffers,
            output_buffers=output_buffers,
        )
        self._attributes = result.attributes

        return result.status, result.expiry


class ServerSecurityContext(SecurityContext):
    """A server security context.

    This represents an SSPI security context that can be used for server side
    authentication. This class is designed to be a high level overlay on top of
    the :class:`sspilib.raw.CtxtHandle` class. it can be used directly with
    any low level API in the ``sspilib.raw`` namespace that requires a context
    handle instance in case the low level interface doesn't expose the methods
    needed.

    The credential stores the credential to use for authentication as well as
    extra information that controls how the security protocol will perform
    the authentication steps.

    By default the flags are set to request mutual auth, replay detection,
    sequence detection, confidentiality, and integrity if no flags are
    specified. Custom flags can be requested but it will overwrite the default
    set.

    Optional channel bindings can be specified which is used to tie the
    security context with an outer channel.

    Properties like ``expiry`` and ``attributes`` won't be populated until the
    context has been negotiated and is complete.

    Args:
        credential: A credential to use for authentication
        flags: Custom ASC REQ flags to use.
        channel_bindings: Optional channel bindings to tie the context to.
    """

    def __init__(
        self,
        credential: raw.CredHandle,
        flags: raw.AscReq | int | None = None,
        *,
        channel_bindings: raw.SecChannelBindings | None = None,
    ) -> None:
        super().__init__(credential=credential, channel_bindings=channel_bindings)
        self._flags = (
            flags
            if flags is not None
            else (
                raw.AscReq.ASC_REQ_MUTUAL_AUTH
                | raw.AscReq.ASC_REQ_REPLAY_DETECT
                | raw.AscReq.ASC_REQ_SEQUENCE_DETECT
                | raw.AscReq.ASC_REQ_CONFIDENTIALITY
                | raw.AscReq.ASC_REQ_INTEGRITY
            )
        )
        self._attributes: raw.AscRet = raw.AscRet(0)

    @property
    def attributes(self) -> raw.AscRet:
        """Attributes of the current security context."""
        return self._attributes

    def _step_internal(
        self,
        input_buffers: raw.SecBufferDesc | None,
        output_buffers: raw.SecBufferDesc | None,
    ) -> tuple[int, int]:
        result = raw.accept_security_context(
            credential=self._credential,
            context=self,
            input_buffers=input_buffers,
            context_req=self._flags | raw.AscReq.ASC_REQ_ALLOCATE_MEMORY,
            target_data_rep=raw.TargetDataRep.SECURITY_NATIVE_DREP,
            output_buffers=output_buffers,
        )
        self._attributes = result.attributes

        status = result.status

        # sspi-rs is weird for NTLM where it returns SEC_I_COMPLETE_NEEDED.
        # Until that bug is fixed and we pull in a new version we need to
        # manually handle that here.
        # https://github.com/Devolutions/sspi-rs/issues/167
        if status == raw.NtStatus.SEC_I_COMPLETE_NEEDED:
            raw.complete_auth_token(self, input_buffers or raw.SecBufferDesc([]))
            status = raw.NtStatus.SEC_E_OK

        return status, result.expiry
