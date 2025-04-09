# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os

import pytest

import sspilib.raw as sr


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support signature functions")
def test_sign_and_verify(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_data = bytearray(client_data)
    in_token = bytearray(sizes.security_trailer)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.make_signature(
        authenticated_contexts[0],
        0,
        in_message,
        0,
    )

    assert bytes(in_data) == client_data
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_data) == in_message[0].data

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_token) == in_message[1].data

    res = sr.verify_signature(
        authenticated_contexts[1],
        in_message,
        0,
    )
    assert res == 0

    assert bytes(in_data) == client_data
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_data) == in_message[0].data

    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_token) == in_message[1].data

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(server_data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.make_signature(
        authenticated_contexts[1],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_data) == server_data
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_data) == in_message[0].data

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_token) == in_message[1].data

    res = sr.verify_signature(
        authenticated_contexts[0],
        in_message,
        0,
    )
    assert res == 0

    assert bytes(in_data) == server_data
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_data) == in_message[0].data

    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_token) == in_message[1].data


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support signature functions")
def test_make_signature_fail(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    data = b"message"

    in_data = bytearray(data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )

    with pytest.raises(sr.WindowsError) as e:
        sr.make_signature(
            authenticated_contexts[0],
            0,
            in_message,
            0,
        )

    assert e.value.winerror == -2146893048  # SEC_E_INVALID_TOKEN


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support signature functions")
def test_verify_failure(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    data = b"message"

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_data = bytearray(data)
    in_token = bytearray(sizes.security_trailer)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.make_signature(
        authenticated_contexts[0],
        0,
        in_message,
        0,
    )

    in_data[0] = 0

    with pytest.raises(sr.WindowsError) as e:
        sr.verify_signature(
            authenticated_contexts[1],
            in_message,
            0,
        )

    assert e.value.winerror == -2146893041  # SEC_E_MESSAGE_ALTERED


def test_encrypt_and_decrypt(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(client_data)
    in_padding = bytearray(sizes.block_size)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_padding, sr.SecBufferType.SECBUFFER_PADDING),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[0],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    res = sr.decrypt_message(
        authenticated_contexts[1],
        in_message,
        0,
    )
    assert res == 0

    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) == client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(server_data)
    in_padding = bytearray(sizes.block_size)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_padding, sr.SecBufferType.SECBUFFER_PADDING),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[1],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    res = sr.decrypt_message(
        authenticated_contexts[0],
        in_message,
        0,
    )
    assert res == 0

    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) == server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data


def test_encrypt_message_fail(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    data = b"message"

    in_data = bytearray(data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )

    with pytest.raises(sr.WindowsError) as e:
        sr.encrypt_message(
            authenticated_contexts[0],
            0,
            in_message,
            0,
        )

    assert e.value.winerror == -2146893048  # SEC_E_INVALID_TOKEN


def test_decrypt_message_failure(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    data = b"message"

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_data = bytearray(data)
    in_token = bytearray(sizes.security_trailer)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[0],
        0,
        in_message,
        0,
    )

    in_data[0] = 0 if in_data[0] == 255 else in_data[0] + 1

    with pytest.raises(sr.WindowsError) as e:
        sr.decrypt_message(
            authenticated_contexts[1],
            in_message,
            0,
        )

    assert e.value.winerror == -2146893041  # SEC_E_MESSAGE_ALTERED


def test_encrypt_and_decrypt_stream(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(client_data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[0],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    stream_data = bytearray(
        b"".join(
            [
                in_message[0].data,
                in_message[1].data,
            ]
        )
    )
    stream_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(stream_data, sr.SecBufferType.SECBUFFER_STREAM),
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_DATA),
        ]
    )
    res = sr.decrypt_message(
        authenticated_contexts[1],
        stream_message,
        0,
    )
    assert res == 0

    assert stream_message[1].data == client_data

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(server_data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[1],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    stream_data = bytearray(
        b"".join(
            [
                in_message[0].data,
                in_message[1].data,
            ]
        )
    )
    stream_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(stream_data, sr.SecBufferType.SECBUFFER_STREAM),
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_DATA),
        ]
    )
    res = sr.decrypt_message(
        authenticated_contexts[0],
        stream_message,
        0,
    )
    assert res == 0

    assert stream_message[1].data == server_data


def test_encrypt_winrm(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(client_data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[0],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    res = sr.decrypt_message(
        authenticated_contexts[1],
        in_message,
        0,
    )
    assert res == 0

    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) == client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    in_token = bytearray(sizes.security_trailer)
    in_data = bytearray(server_data)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[1],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) != server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    res = sr.decrypt_message(
        authenticated_contexts[0],
        in_message,
        0,
    )
    assert res == 0

    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_token) == in_message[0].data

    assert bytes(in_data) == server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data


@pytest.mark.parametrize(
    ["sign_header"],
    [
        (True,),
        (False,),
    ],
)
def test_encrypt_dce(
    sign_header: bool,
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    if os.name != "nt" and not sign_header:
        pytest.skip(reason="sspi-rs fails to decrypt the payloads with SECBUFFER_READONLY")

    buffer_flags = (
        sr.SecBufferFlags.SECBUFFER_READONLY_WITH_CHECKSUM if sign_header else sr.SecBufferFlags.SECBUFFER_READONLY
    )
    client_data = os.urandom(32)
    client_header = os.urandom(24)
    client_trailer = os.urandom(8)

    server_data = os.urandom(32)
    server_header = os.urandom(24)
    server_trailer = os.urandom(8)

    sizes = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)

    in_header = bytearray(client_header)
    in_data = bytearray(client_data)
    in_trailer = bytearray(client_trailer)
    in_token = bytearray(sizes.security_trailer)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_header, sr.SecBufferType.SECBUFFER_DATA, buffer_flags),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_trailer, sr.SecBufferType.SECBUFFER_DATA, buffer_flags),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[0],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_header) == client_header
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_header) == in_message[0].data

    assert bytes(in_data) != client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    assert bytes(in_trailer) == client_trailer
    assert len(in_message[2].data) == in_message[2].count
    assert bytes(in_trailer) == in_message[2].data

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[3].data) == in_message[3].count
    assert bytes(in_token) == in_message[3].data

    res = sr.decrypt_message(
        authenticated_contexts[1],
        in_message,
        0,
    )
    assert res == 0

    assert bytes(in_header) == client_header
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_header) == in_message[0].data

    assert bytes(in_data) == client_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    assert bytes(in_trailer) == client_trailer
    assert len(in_message[2].data) == in_message[2].count
    assert bytes(in_trailer) == in_message[2].data

    assert len(in_message[3].data) == in_message[3].count
    assert bytes(in_token) == in_message[3].data

    in_header = bytearray(server_header)
    in_data = bytearray(server_data)
    in_trailer = bytearray(server_trailer)
    in_token = bytearray(sizes.security_trailer)
    in_message = sr.SecBufferDesc(
        [
            sr.SecBuffer(in_header, sr.SecBufferType.SECBUFFER_DATA, buffer_flags),
            sr.SecBuffer(in_data, sr.SecBufferType.SECBUFFER_DATA),
            sr.SecBuffer(in_trailer, sr.SecBufferType.SECBUFFER_DATA, buffer_flags),
            sr.SecBuffer(in_token, sr.SecBufferType.SECBUFFER_TOKEN),
        ],
    )
    sr.encrypt_message(
        authenticated_contexts[1],
        sr.QopFlags(0),
        in_message,
        0,
    )

    assert bytes(in_header) == server_header
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_header) == in_message[0].data

    assert bytes(in_data) != server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    assert bytes(in_trailer) == server_trailer
    assert len(in_message[2].data) == in_message[2].count
    assert bytes(in_trailer) == in_message[2].data

    assert bytes(in_token) != b"\x00" * sizes.security_trailer
    assert len(in_message[3].data) == in_message[3].count
    assert bytes(in_token) == in_message[3].data

    res = sr.decrypt_message(
        authenticated_contexts[0],
        in_message,
        0,
    )
    assert res == 0

    assert bytes(in_header) == server_header
    assert len(in_message[0].data) == in_message[0].count
    assert bytes(in_header) == in_message[0].data

    assert bytes(in_data) == server_data
    assert len(in_message[1].data) == in_message[1].count
    assert bytes(in_data) == in_message[1].data

    assert bytes(in_trailer) == server_trailer
    assert len(in_message[2].data) == in_message[2].count
    assert bytes(in_trailer) == in_message[2].data

    assert len(in_message[3].data) == in_message[3].count
    assert bytes(in_token) == in_message[3].data
