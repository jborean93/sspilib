# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import sspi


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

    view = buffer.dangerous_get_view()
    assert bytes(view) == b"\x00" * 32


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

    view = buffer.dangerous_get_view()
    assert bytes(view) == b"".join(
        [
            b"\x01\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00",
            b"\x00" * 20,
            b"12\x003",
        ]
    )
    assert bytes(view) == (b"\x01\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00" + (b"\x00" * 20) + b"12\x003")


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

    view = buffer.dangerous_get_view()
    assert bytes(view) == b"".join(
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

    view = buffer.dangerous_get_view()
    view = buffer.dangerous_get_view()
    assert bytes(view) == b"".join(
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

    view = buffer.dangerous_get_view()
    assert bytes(view) == b"".join(
        [
            b"\x01\x00\x00\x00\x01\x00\x00\x00\x20\x00\x00\x00",
            b"\x02\x00\x00\x00\x01\x00\x00\x00\x21\x00\x00\x00",
            b"\x01\x00\x00\x00\x22\x00\x00\x00",
            b"123",
        ]
    )
