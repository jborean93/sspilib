# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import json
import os
import socket

import pytest

import sspilib


@dataclasses.dataclass(frozen=True)
class KerberosEnvironment:
    """Details of the Kerberos realm the tests can authenticate with.

    The values come from the JSON in the SSPILIB_KRB_CONFIG environment
    variable set by build_helpers/kerberos-env.ps1 which runs the tests with
    an Obol KDC. The field names are the keys of that JSON object.
    """

    realm: str
    user: str
    password: str
    keytab_user: str
    keytab_user_keytab: str
    service: str
    service_keytab: str


@pytest.fixture(scope="session")
def krb_env() -> KerberosEnvironment:
    if os.name != "nt":
        pytest.skip("sspi-rs cannot accept Kerberos tokens through SSPI, it has no keytab support")

    config = os.environ.get("SSPILIB_KRB_CONFIG")
    if not config:
        pytest.skip("SSPILIB_KRB_CONFIG is not set, run the tests with build_helpers/kerberos-env.ps1 to use a KDC")

    return KerberosEnvironment(**json.loads(config))


@pytest.fixture(params=["NTLM", "Kerberos", "Negotiate"])
def initial_contexts(
    request: pytest.FixtureRequest,
) -> tuple[sspilib.ClientSecurityContext, sspilib.ServerSecurityContext]:
    protocol = request.param
    c_cred: sspilib.raw.CredHandle
    s_cred: sspilib.raw.CredHandle

    if protocol == "NTLM":
        spn = f"host/{socket.gethostname()}"

        # sspi-rs only supports acceptors for NTLM at this point in time. it also
        # cannot rely on implicit creds
        if os.name == "nt":
            c_cred = sspilib.UserCredential(protocol="NTLM")
            s_cred = sspilib.UserCredential(usage="accept")
        else:
            c_cred = sspilib.UserCredential("user", "pass", protocol="NTLM")
            s_cred = sspilib.UserCredential("user", "pass", protocol="NTLM", usage="accept")

    else:
        # Kerberos needs a KDC, the krb_env fixture skips the test when there
        # is none. The acceptor uses the service keytab exported from the KDC.
        # Negotiate goes through SPNEGO with NTLM disabled so it must select
        # Kerberos.
        krb_env: KerberosEnvironment = request.getfixturevalue("krb_env")
        spn = krb_env.service
        protocol_list = ["!ntlm"] if protocol == "Negotiate" else None

        c_cred = sspilib.UserCredential(
            krb_env.user,
            krb_env.password,
            protocol=protocol,
            protocol_list=protocol_list,
        )
        s_cred = sspilib.KeytabCredential(
            krb_env.service,
            krb_env.service_keytab,
            protocol=protocol,
            usage="accept",
            protocol_list=protocol_list,
        )

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
