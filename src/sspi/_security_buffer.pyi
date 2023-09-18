# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

SECBUFFER_VERSION: int = 0  #: Constant for SecBufferDesc version

class SecBufferFlags(enum.IntFlag):
    """Security buffer flags."""

    SECBUFFER_NONE = ...
    """No flags are set."""
    SECBUFFER_ATTRMASK = ...
    """Bitmask for the security buffer flags."""
    SECBUFFER_READONLY = ...
    """The buffer is read-only with no checksum."""
    SECBUFFER_READONLY_WITH_CHECKSUM = ...
    """The buffer is read-only with a checksum."""
    SECBUFFER_RESERVED = ...
    """Flags reserved to the security system."""

class SecBufferType(enum.IntEnum):
    """The type of security buffer."""

    SECBUFFER_EMPTY = ...
    """This is a placeholder in the buffer array."""
    SECBUFFER_DATA = ...
    """The buffer contains common data."""
    SECBUFFER_TOKEN = ...
    """The buffer contains the security token portion of the message."""
    SECBUFFER_PKG_PARAMS = ...
    """These are transport-to-package-specific parameters."""
    SECBUFFER_MISSING = ...
    """The security package uses this value to indicate the number of missing bytes in a particular message."""
    SECBUFFER_EXTRA = ...
    """The security package uses this value to indicate the number of extra or unprocessed bytes in a message."""
    SECBUFFER_STREAM_TRAILER = ...
    """The buffer contains a protocol-specific trailer for a particular record."""
    SECBUFFER_STREAM_HEADER = ...
    """The buffer contains a protocol-specific header for a particular record."""
    SECBUFFER_NEGOTIATION_INFO = ...
    """The buffer contains hints from the negotiation package."""
    SECBUFFER_PADDING = ...
    """The buffer contains non-data padding."""
    SECBUFFER_STREAM = ...
    """The buffer contains the whole encrypted message."""
    SECBUFFER_MECHLIST = ...
    """The buffer contains a protocol-specific list of OIDs."""
    SECBUFFER_MECHLIST_SIGNATURE = ...
    """THe buffer contains a signature of the SECBUFFER_MECHLIST buffer."""
    SECBUFFER_TARGET = ...
    """This flag is reserved. Do not use it."""
    SECBUFFER_CHANNEL_BINDINGS = ...
    """The buffer contains channel binding information."""
    SECBUFFER_CHANGE_PASS_RESPONSE = ...
    """The buffer contains a DOMAIN_PASSWORD_INFORMATION structure."""
    SECBUFFER_TARGET_HOST = ...
    """The buffer specifies the SPN of the target."""
    SECBUFFER_ALERT = ...
    """The buffer contains an alert message."""
    SECBUFFER_APPLICATION_PROTOCOLS = ...
    """The buffer contains a list of application protocol IDs."""
    SECBUFFER_SRTP_PROTECTION_PROFILES = ...
    """The buffer contains the list of SRTP protection profiles."""
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = ...
    """The buffer contains the SRTP master key identitifer."""
    SECBUFFER_TOKEN_BINDING = ...
    """The buffer contains the supported token binding protocol version and key parameters."""
    SECBUFFER_PRESHARED_KEY = ...
    """The buffer contains the preshared key."""
    SECBUFFER_PRESHARED_KEY_IDENTITY = ...
    """The buffer contains the preshared key identity."""
    SECBUFFER_DTLS_MTU = ...
    """The buffer contains the setting for the maximum transmission unit size of DTLS."""
    SECBUFFER_SEND_GENERIC_TLS_EXTENSION = ...
    """The buffer contains generic TLS extensions for sending."""
    SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION = ...
    """The buffer contains generic TLS extensions for subscribing."""
    SECBUFFER_FLAGS = ...
    """The buffer contains the ISC/ASC REQ flags."""
    SECBUFFER_TRAFFIC_SECRETS = ...
    """The buffer contains message sequence lengths and corresponding traffic secrets."""
    SECBUFFER_CERTIFICATE_REQUEST_CONTEXT = ...
    """The buffer contains the TLS 1.3 certificate request context."""

class SecBufferDesc:
    """An array of SecBuffer structures.

    This type is used to encapsulate an array of :class:`SecBuffer` instances
    used for exchanging data with a security package. The array size and values
    are immutable once created.

    Args:
        buffers: A list of SecBuffer values to include in this array.
        version: The version number of the structure, defaults to
            SECBUFFER_VERSION.
    """

    def __init__(
        self,
        buffers: list[SecBuffer],
        *,
        version: int = SECBUFFER_VERSION,
    ) -> None: ...
    def __iter__(self) -> list[SecBuffer]:
        """Creates an iterable of the contained buffers."""
    def __l0en__(self) -> int:
        """Returns the number of buffers in this structure."""
    def __getitem__(self, key: int) -> SecBuffer:
        """Gets the buffer at the specified index."""
    @property
    def version(self) -> int:
        """The version number of the structure."""

class SecBuffer:
    """A security package buffer.

    A buffer used to exchange data to and from a security package operation.
    Depending on the buffer type and operation, the data might be mutated in
    place by the security package.

    The ``data`` property will create a copy of the buffer bytes while
    :meth:`dangerous_get_view` can be used to get a view of the data pointed by
    the buffer without any copying. Be careful not to use the view returned
    once the buffer has been freed.

    Args:
        data: A bytearray or memoryview to a writable bytes buffer containing
            the buffer data. Can be None if using an empty data buffer.
        buffer_type: The buffer type.
        buffer_flags: Any buffer flags to associate with the data, defaults to
            no flags.
    """

    def __init__(
        self,
        data: bytearray | memoryview | None,
        buffer_type: SecBufferType | int,
        buffer_flags: SecBufferFlags | int = 0,
    ) -> None: ...
    @property
    def count(self) -> int:
        """The length of the buffer."""
    @property
    def data(self) -> bytes:
        """A copy of the buffer bytes."""
    @property
    def buffer_type(self) -> SecBufferType:
        """The buffer type."""
    @property
    def buffer_flags(self) -> SecBufferFlags:
        """The buffer flags."""
    def dangerous_get_view(self) -> memoryview:
        """The buffer memoryview.

        This returns a memoryview to the raw buffer bytes in memory. While this
        does not copy the data from the buffer, it is only valid if the class
        instance has not been deallocated. As the memoryview is a reference to
        unmanaged memory it is critical that the view is not used once the
        buffer is deallocated. To get a copy of the bytes in a safer fashion
        use :meth:`data`.
        """

class SecChannelBindings:
    """Channel binding information.

    Specifies channel binding information for a security context. SSPI only
    uses the application_data property but others might used for interop with
    other implementations. Any value passed in will be copied to an internal
    buffer as SSPI requires it to be placed in contiguous memory. The properties
    will return a copy of the values if set as well.

    Use :meth:`dangerous_get_view` to get a raw writable view of the internal
    data structure for use in a :class:`SecBuffer` value. Be careful as this
    view is only valid for the life of the object it came from. Editing the
    values or using once the structure was deallocated can cause undefined
    behaviour.

    Args:
        initiator_addr_type: The type of the initiator/client address.
        initiator_addr: The initiator address.
        acceptor_addr_type: The type of the acceptor/server address.
        acceptor_addr: The acceptor address.
        application_data: The channel binding data.
    """

    def __init__(
        self,
        *,
        initiator_addr_type: int = 0,
        initiator_addr: bytes | bytearray | memoryview | None = None,
        acceptor_addr_type: int = 0,
        acceptor_addr: bytes | bytearray | memoryview | None = None,
        application_data: bytes | bytearray | memoryview | None = None,
    ) -> None: ...
    @property
    def initiator_addr_type(self) -> int:
        """The initiator address type."""
    @property
    def initiator_addr(self) -> bytes | None:
        """A copy of the initiator address or None if not present."""
    @property
    def acceptor_addr_type(self) -> int:
        """The acceptor address type."""
    @property
    def acceptor_addr(self) -> bytes | None:
        """A copy of the acceptor address or None if not present."""
    @property
    def application_data(self) -> bytes | None:
        """A copy of the application data or None if not present."""
    def dangerous_get_view(self) -> memoryview:
        """The structure memoryview.

        This returns a memoryview to the raw structs bytes in memory. While
        this does not copy the data from the pointer, it is only valid if the
        class instance has not been deallocated. As the memoryview is a
        reference to unmanaged memory, it is critical that the view is not used
        onces the buffer is deallocated.
        """
