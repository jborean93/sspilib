# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import json
import os
import socket
import time
import warnings

import pytest

import sspilib


@dataclasses.dataclass(frozen=True)
class KerberosEnvironment:
    """Details of the Kerberos realm the tests can authenticate with.

    The values come from the JSON in the SSPILIB_TEST_KERBEROS environment
    variable set by build_helpers/run-with-kdc.ps1 which runs the tests with
    an Obol KDC. The field names are the keys of that JSON object.

    Attributes:
        realm: The name of the realm.
        initiator_username: The initiator's user principal, in UPN form.
        initiator_password: The password for the initiator
        initiator_keytab: Path to a keytab for the initiator.
        acceptor_spn: The SPN of the acceptor.
        acceptor_keytab: Path to a keytab for the acceptor.
    """

    realm: str
    initiator_username: str
    initiator_password: str
    initiator_keytab: str
    acceptor_spn: str
    acceptor_keytab: str


@pytest.fixture(scope="session")
def krb_env() -> KerberosEnvironment:
    if os.name != "nt":
        pytest.skip("sspi-rs cannot accept Kerberos tokens through SSPI, it has no keytab support")

    config = os.environ.get("SSPILIB_TEST_KERBEROS")
    if not config:
        pytest.skip("SSPILIB_TEST_KERBEROS is not set, run the tests with build_helpers/run-with-kdc.ps1 to use a KDC")

    env = KerberosEnvironment(**json.loads(config))
    _warm_up_sspi(env)

    return env


def _warm_up_sspi(env: KerberosEnvironment, attempts: int = 5, delay: float = 2.0) -> None:
    """Authenticates once with Kerberos before the tests use the realm.

    On a freshly started Windows CI runner the first SSPI Kerberos acceptor
    can fail to acquire its keytab credential with SEC_E_NO_CREDENTIALS, later
    ones succeed. The exchange is retried so the first test does not hit this,
    each failure is emitted as a warning so it shows in the test summary.
    """
    for attempt in range(1, attempts + 1):
        try:
            c_cred = sspilib.UserCredential(env.initiator_username, env.initiator_password, protocol="Kerberos")
            s_cred = sspilib.KeytabCredential(
                env.acceptor_spn, env.acceptor_keytab, protocol="Kerberos", usage="accept"
            )
            c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=env.acceptor_spn)
            s_ctx = sspilib.ServerSecurityContext(credential=s_cred)

            s_token = None
            while not (c_ctx.complete and not s_token):
                c_token = c_ctx.step(s_token)
                s_token = s_ctx.step(c_token) if c_token else None

            return

        except sspilib.raw.WindowsError as e:
            warnings.warn(f"SSPI Kerberos warm up attempt {attempt}/{attempts} failed: {e}")
            if attempt == attempts:
                raise

            time.sleep(delay)


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
        spn = krb_env.acceptor_spn
        protocol_list = ["!ntlm"] if protocol == "Negotiate" else None

        c_cred = sspilib.UserCredential(
            krb_env.initiator_username,
            krb_env.initiator_password,
            protocol=protocol,
            protocol_list=protocol_list,
        )
        s_cred = sspilib.KeytabCredential(
            spn,
            krb_env.acceptor_keytab,
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
