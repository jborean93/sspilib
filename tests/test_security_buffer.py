# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pytest

import sspi


def test_empty_sec_buffer_desc() -> None:
    buffers = sspi.SecBufferDesc([])
    assert len(buffers) == 0
    assert list(iter(buffers)) == []
    assert buffers.version == 0


def test_sec_buffer_desc_version() -> None:
    buffers = sspi.SecBufferDesc([], version=1)
    assert buffers.version == 1


def test_sec_buffer_desc_indexing() -> None:
    buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(bytearray(b"1"), sspi.SecBufferType.SECBUFFER_DATA, sspi.SecBufferFlags.SECBUFFER_READONLY),
            sspi.SecBuffer(bytearray(b"2"), sspi.SecBufferType.SECBUFFER_TOKEN),
            sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_PADDING),
        ]
    )

    assert len(buffers) == 3

    assert isinstance(buffers[0], sspi.SecBuffer)
    assert buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_DATA
    assert buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_READONLY
    assert buffers[0].count == 1
    assert buffers[0].data == b"1"

    assert isinstance(buffers[1], sspi.SecBuffer)
    assert buffers[1].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert buffers[1].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE
    assert buffers[1].count == 1
    assert buffers[1].data == b"2"

    assert isinstance(buffers[2], sspi.SecBuffer)
    assert buffers[2].buffer_type == sspi.SecBufferType.SECBUFFER_PADDING
    assert buffers[2].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE
    assert buffers[2].count == 0
    assert buffers[2].data == b""

    assert buffers[-1] == buffers[2]
    assert buffers[-2] == buffers[1]
    assert buffers[-3] == buffers[0]

    with pytest.raises(IndexError):
        buffers[3]

    with pytest.raises(IndexError):
        buffers[-4]


def test_sec_buffer_bytearray() -> None:
    data = bytearray(b"data")
    buffer = sspi.SecBuffer(data, sspi.SecBufferType.SECBUFFER_DATA)

    assert buffer.count == 4
    assert buffer.data == b"data"
    assert buffer.buffer_type == sspi.SecBufferType.SECBUFFER_DATA
    assert buffer.buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE
    assert repr(buffer) == "SecBuffer(data=bytearray(b'data'), buffer_type=1, buffer_flags=0)"
    assert str(buffer) == "SECBUFFER_DATA"
    assert bytes(buffer.dangerous_get_view()) == b"data"


def test_sec_buffer_memoryview() -> None:
    data = bytearray(b"data")
    buffer = sspi.SecBuffer(
        memoryview(data),
        sspi.SecBufferType.SECBUFFER_TOKEN,
        sspi.SecBufferFlags.SECBUFFER_READONLY_WITH_CHECKSUM,
    )

    assert buffer.count == 4
    assert buffer.data == b"data"
    assert buffer.buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert buffer.buffer_flags == sspi.SecBufferFlags.SECBUFFER_READONLY_WITH_CHECKSUM
    assert repr(buffer) == "SecBuffer(data=bytearray(b'data'), buffer_type=2, buffer_flags=268435456)"
    assert str(buffer) == "SECBUFFER_TOKEN|SECBUFFER_READONLY_WITH_CHECKSUM"
    assert bytes(buffer.dangerous_get_view()) == b"data"


def test_sec_buffer_empty() -> None:
    data = bytearray(b"")
    buffer = sspi.SecBuffer(data, sspi.SecBufferType.SECBUFFER_DATA)

    assert buffer.count == 0
    assert buffer.data == b""
    assert buffer.buffer_type == sspi.SecBufferType.SECBUFFER_DATA
    assert buffer.buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE
    assert repr(buffer) == "SecBuffer(data=bytearray(b''), buffer_type=1, buffer_flags=0)"
    assert str(buffer) == "SECBUFFER_DATA"
    assert bytes(buffer.dangerous_get_view()) == b""


def test_sec_buffer_none() -> None:
    buffer = sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_DATA)

    assert buffer.count == 0
    assert buffer.data == b""
    assert buffer.buffer_type == sspi.SecBufferType.SECBUFFER_DATA
    assert buffer.buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE
    assert repr(buffer) == "SecBuffer(data=bytearray(b''), buffer_type=1, buffer_flags=0)"
    assert str(buffer) == "SECBUFFER_DATA"
    assert bytes(buffer.dangerous_get_view()) == b""


def test_sec_channel_bindings_nothing() -> None:
    buffer = sspi.SecChannelBindings()
    assert (
        repr(buffer)
        == "SecChannelBindings(initiator_addr_type=0, initiator_addr=None, acceptor_addr_type=0, acceptor_addr=None, application_data=None)"
    )
    assert buffer.initiator_addr_type == 0
    assert buffer.initiator_addr is None
    assert buffer.acceptor_addr_type == 0
    assert buffer.acceptor_addr is None
    assert buffer.application_data is None

    data = buffer.get_sec_buffer_copy().data
    assert data == b"\x00" * 32


def test_sec_channel_bindings_initiator() -> None:
    buffer = sspi.SecChannelBindings(initiator_addr_type=1, initiator_addr=b"12\x003")
    assert (
        repr(buffer)
        == "SecChannelBindings(initiator_addr_type=1, initiator_addr=b'12\\x003', acceptor_addr_type=0, acceptor_addr=None, application_data=None)"
    )
    assert buffer.initiator_addr_type == 1
    assert buffer.initiator_addr == b"12\x003"
    assert buffer.acceptor_addr_type == 0
    assert buffer.acceptor_addr is None
    assert buffer.application_data is None

    data = buffer.get_sec_buffer_copy().data
    assert data == b"".join(
        [
            b"\x01\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00",
            b"\x00" * 20,
            b"12\x003",
        ]
    )


def test_sec_channel_bindings_acceptor() -> None:
    buffer = sspi.SecChannelBindings(acceptor_addr_type=1, acceptor_addr=b"12\x003")
    assert (
        repr(buffer)
        == "SecChannelBindings(initiator_addr_type=0, initiator_addr=None, acceptor_addr_type=1, acceptor_addr=b'12\\x003', application_data=None)"
    )
    assert buffer.initiator_addr_type == 0
    assert buffer.initiator_addr is None
    assert buffer.acceptor_addr_type == 1
    assert buffer.acceptor_addr == b"12\x003"
    assert buffer.application_data is None

    data = buffer.get_sec_buffer_copy().data
    assert data == b"".join(
        [
            b"\x00" * 12,
            b"\x01\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00",
            b"\x00" * 8,
            b"12\x003",
        ]
    )


def test_sec_channel_bindings_appdata() -> None:
    buffer = sspi.SecChannelBindings(application_data=b"12\x003")
    assert (
        repr(buffer)
        == "SecChannelBindings(initiator_addr_type=0, initiator_addr=None, acceptor_addr_type=0, acceptor_addr=None, application_data=b'12\\x003')"
    )
    assert buffer.initiator_addr_type == 0
    assert buffer.initiator_addr is None
    assert buffer.acceptor_addr_type == 0
    assert buffer.acceptor_addr is None
    assert buffer.application_data == b"12\x003"

    data = buffer.get_sec_buffer_copy().data
    assert data == b"".join(
        [
            b"\x00" * 24,
            b"\x04\x00\x00\x00\x20\x00\x00\x0012\x003",
        ]
    )


def test_sec_channel_bindings_all() -> None:
    buffer = sspi.SecChannelBindings(
        initiator_addr_type=1,
        initiator_addr=b"1",
        acceptor_addr_type=2,
        acceptor_addr=b"2",
        application_data=b"3",
    )
    assert (
        repr(buffer)
        == "SecChannelBindings(initiator_addr_type=1, initiator_addr=b'1', acceptor_addr_type=2, acceptor_addr=b'2', application_data=b'3')"
    )
    assert buffer.initiator_addr_type == 1
    assert buffer.initiator_addr == b"1"
    assert buffer.acceptor_addr_type == 2
    assert buffer.acceptor_addr == b"2"
    assert buffer.application_data == b"3"

    data = buffer.get_sec_buffer_copy().data
    assert data == b"".join(
        [
            b"\x01\x00\x00\x00\x01\x00\x00\x00\x20\x00\x00\x00",
            b"\x02\x00\x00\x00\x01\x00\x00\x00\x21\x00\x00\x00",
            b"\x01\x00\x00\x00\x22\x00\x00\x00",
            b"123",
        ]
    )


def test_sec_channel_bindings_dangerous_get_buffer() -> None:
    channel_bindings = sspi.SecChannelBindings(application_data=b"12\x003")
    expected = b"".join(
        [
            b"\x00" * 24,
            b"\x04\x00\x00\x00\x20\x00\x00\x0012\x003",
        ]
    )

    safe_buffer = channel_bindings.get_sec_buffer_copy()
    unsafe_buffer = channel_bindings.dangerous_get_sec_buffer()

    safe_buffer.data == expected
    unsafe_buffer.data == expected

    # Modifying the raw bytes should reflect back on the channel_bindings val
    unsafe_buffer.dangerous_get_view()[0] = b"\x01"  # type: ignore[call-overload]
    assert channel_bindings.initiator_addr_type == 1

    # It should not affect the safe buffer created with a copy
    assert safe_buffer.data == expected
    assert unsafe_buffer.data == b"".join(
        [
            b"\x01",
            b"\x00" * 23,
            b"\x04\x00\x00\x00\x20\x00\x00\x0012\x003",
        ]
    )

    # The safe buffer should still be valid beyond the life of the object
    del channel_bindings
    safe_buffer.data == expected
