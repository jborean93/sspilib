# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os
import socket

import pytest

import sspilib


@pytest.fixture()
def initial_contexts() -> tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext]:
    spn = f"host/{socket.gethostname()}"

    # sspi-rs only supports acceptors for NTLM at this point in time. it also
    # cannot rely on implicit creds
    if os.name == "nt":
        c_cred = sspilib.UserCredential(protocol="NTLM")
        s_cred = sspilib.UserCredential(usage="accept")
    else:
        c_cred = sspilib.UserCredential("user", "pass", protocol="NTLM")
        s_cred = sspilib.UserCredential("user", "pass", protocol="NTLM", usage="accept")

    c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=spn)
    s_ctx = sspilib.ServerSecurityContext(credential=s_cred)

    return c_ctx, s_ctx


@pytest.fixture()
def authenticated_contexts(
    initial_contexts: tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext],
) -> tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext]:
    c_ctx, s_ctx = initial_contexts

    s_token = None
    while not (c_ctx.complete and not s_token):
        c_token = c_ctx.step(s_token)

        if c_token:
            s_token = s_ctx.step(c_token)
        else:
            s_token = None

    assert c_ctx.complete
    assert s_ctx.complete

    return c_ctx, s_ctx
