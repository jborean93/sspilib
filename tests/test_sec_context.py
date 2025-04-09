# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import datetime
import os

import pytest

import sspilib


def test_sec_context_attributes(
    initial_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    c_ctx, s_ctx = initial_contexts

    assert not c_ctx.complete
    assert c_ctx.expiry == datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
    assert c_ctx.attributes == sspilib.IscRet(0)

    assert not s_ctx.complete
    assert s_ctx.expiry == datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
    assert s_ctx.attributes == sspilib.AscRet(0)

    s_token = None
    while not (c_ctx.complete and not s_token):
        c_token = c_ctx.step(s_token)

        if c_token:
            s_token = s_ctx.step(c_token)
        else:
            s_token = None

    assert c_ctx.complete
    assert isinstance(c_ctx.expiry, datetime.datetime)
    assert c_ctx.attributes != sspilib.IscRet(0)

    assert s_ctx.complete
    assert isinstance(s_ctx.expiry, datetime.datetime)
    assert s_ctx.attributes != sspilib.AscRet(0)


def test_sec_context_wrapping(
    authenticated_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)
    c_ctx, s_ctx = authenticated_contexts

    wrapped_data = c_ctx.wrap(client_data)
    assert wrapped_data != client_data

    unwrapped_data = s_ctx.unwrap(wrapped_data)
    assert isinstance(unwrapped_data, sspilib.UnwrapResult)
    assert unwrapped_data.qop == 0
    assert unwrapped_data.data == client_data

    wrapped_data = s_ctx.wrap(server_data)
    assert wrapped_data != server_data

    unwrapped_data = c_ctx.unwrap(wrapped_data)
    assert isinstance(unwrapped_data, sspilib.UnwrapResult)
    assert unwrapped_data.qop == 0
    assert unwrapped_data.data == server_data


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support signatures yet")
def test_sec_context_signatures(
    authenticated_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    client_data = os.urandom(32)
    server_data = os.urandom(32)
    c_ctx, s_ctx = authenticated_contexts

    c_signature = c_ctx.sign(client_data)
    s_ctx.verify(client_data, c_signature)

    s_signature = s_ctx.sign(server_data)
    c_ctx.verify(server_data, s_signature)


def test_wrap_with_bytearray(
    authenticated_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    client_data = os.urandom(32)
    b_client_data = bytearray(client_data)
    c_ctx, s_ctx = authenticated_contexts

    wrapped_data = c_ctx.wrap(b_client_data)
    assert bytes(b_client_data) != client_data  # See if it's mutated in place
    assert wrapped_data != client_data

    if os.name != "nt":
        return

    b_wrapped_data = bytearray(wrapped_data)
    unwrapped_data = s_ctx.unwrap(b_wrapped_data)
    assert isinstance(unwrapped_data, sspilib.UnwrapResult)
    assert unwrapped_data.qop == 0
    assert unwrapped_data.data == client_data
    assert bytes(b_wrapped_data) != wrapped_data


def test_wrap_with_writable_memoryview(
    authenticated_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    client_data = os.urandom(32)
    b_client_data = memoryview(bytearray(client_data))
    c_ctx, s_ctx = authenticated_contexts

    wrapped_data = c_ctx.wrap(b_client_data)
    assert bytes(b_client_data) != client_data  # See if it's mutated in place
    assert wrapped_data != client_data

    if os.name != "nt":
        return

    b_wrapped_data = memoryview(bytearray(wrapped_data))
    unwrapped_data = s_ctx.unwrap(b_wrapped_data)
    assert isinstance(unwrapped_data, sspilib.UnwrapResult)
    assert unwrapped_data.qop == 0
    assert unwrapped_data.data == client_data
    assert bytes(b_wrapped_data) != wrapped_data


def test_wrap_with_readonly_memoryview(
    authenticated_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> None:
    client_data = os.urandom(32)
    b_client_data = memoryview(client_data)
    c_ctx, s_ctx = authenticated_contexts

    wrapped_data = c_ctx.wrap(b_client_data)
    assert bytes(b_client_data) == client_data
    assert wrapped_data != client_data

    if os.name != "nt":
        return

    b_wrapped_data = memoryview(wrapped_data)
    unwrapped_data = s_ctx.unwrap(b_wrapped_data)
    assert isinstance(unwrapped_data, sspilib.UnwrapResult)
    assert unwrapped_data.qop == 0
    assert unwrapped_data.data == client_data
    assert bytes(b_wrapped_data) == wrapped_data
