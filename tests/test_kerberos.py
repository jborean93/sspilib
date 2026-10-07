# Copyright: (c) 2026 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Kerberos specific scenarios.

The end to end exchanges for Kerberos and Negotiate are covered by the
protocol parametrized fixtures in conftest.py. These tests cover the Kerberos
specific credential and failure scenarios. They need a KDC and are skipped
unless the krb_env fixture finds one, run them through
build_helpers/run-with-kdc.ps1 which starts an Obol KDC. They only run on
Windows as sspi-rs cannot accept Kerberos tokens or use keytab credentials.
"""

from __future__ import annotations

import os
import typing as t

import pytest

import sspilib
import sspilib.raw as sr

if t.TYPE_CHECKING:
    from conftest import KerberosEnvironment


def exchange(
    c_ctx: sspilib.ClientSecurityContext,
    s_ctx: sspilib.ServerSecurityContext,
) -> None:
    s_token = None
    while not (c_ctx.complete and not s_token):
        c_token = c_ctx.step(s_token)

        if c_token:
            s_token = s_ctx.step(c_token)
        else:
            s_token = None

    assert c_ctx.complete
    assert s_ctx.complete


def test_kerberos_mutual_auth(krb_env: KerberosEnvironment) -> None:
    c_cred = sspilib.UserCredential(
        krb_env.initiator_username,
        krb_env.initiator_password,
        protocol="Kerberos",
    )
    s_cred = sspilib.KeytabCredential(
        krb_env.acceptor_spn,
        krb_env.acceptor_keytab,
        protocol="Kerberos",
        usage="accept",
    )

    c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=krb_env.acceptor_spn)
    s_ctx = sspilib.ServerSecurityContext(credential=s_cred)
    exchange(c_ctx, s_ctx)

    # The client requested mutual auth so the acceptor must have sent back
    # the AP-REP the client verified.
    assert c_ctx.attributes & sspilib.IscRet.ISC_RET_MUTUAL_AUTH
    assert s_ctx.attributes & sspilib.AscRet.ASC_RET_MUTUAL_AUTH


def test_kerberos_keytab_initiator(krb_env: KerberosEnvironment) -> None:
    c_cred = sspilib.KeytabCredential(
        krb_env.initiator_username,
        krb_env.initiator_keytab,
        protocol="Kerberos",
    )
    s_cred = sspilib.KeytabCredential(
        krb_env.acceptor_spn,
        krb_env.acceptor_keytab,
        protocol="Kerberos",
        usage="accept",
    )

    c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=krb_env.acceptor_spn)
    s_ctx = sspilib.ServerSecurityContext(credential=s_cred)
    exchange(c_ctx, s_ctx)

    assert c_ctx.attributes & sspilib.IscRet.ISC_RET_MUTUAL_AUTH
    assert s_ctx.attributes & sspilib.AscRet.ASC_RET_MUTUAL_AUTH

    data = os.urandom(32)
    assert s_ctx.unwrap(c_ctx.wrap(data)).data == data
    assert c_ctx.unwrap(s_ctx.wrap(data)).data == data


def test_kerberos_keytab_acceptor_from_bytes(krb_env: KerberosEnvironment) -> None:
    with open(krb_env.acceptor_keytab, mode="rb") as fd:
        keytab = fd.read()

    c_cred = sspilib.UserCredential(
        krb_env.initiator_username,
        krb_env.initiator_password,
        protocol="Kerberos",
    )
    s_cred = sspilib.KeytabCredential(
        krb_env.acceptor_spn,
        keytab,
        protocol="Kerberos",
        usage="accept",
    )

    c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=krb_env.acceptor_spn)
    s_ctx = sspilib.ServerSecurityContext(credential=s_cred)
    exchange(c_ctx, s_ctx)

    data = os.urandom(32)
    assert s_ctx.unwrap(c_ctx.wrap(data)).data == data


def test_kerberos_wrong_password(krb_env: KerberosEnvironment) -> None:
    cred = sspilib.UserCredential(
        krb_env.initiator_username,
        f"{krb_env.initiator_password}-wrong",
        protocol="Kerberos",
    )
    ctx = sspilib.ClientSecurityContext(credential=cred, target_name=krb_env.acceptor_spn)

    with pytest.raises(sr.WindowsError):
        ctx.step()


def test_kerberos_unknown_service(krb_env: KerberosEnvironment) -> None:
    cred = sspilib.UserCredential(
        krb_env.initiator_username,
        krb_env.initiator_password,
        protocol="Kerberos",
    )
    ctx = sspilib.ClientSecurityContext(credential=cred, target_name=f"HTTP/missing.{krb_env.realm.lower()}")

    with pytest.raises(sr.WindowsError):
        ctx.step()


def test_kerberos_acceptor_wrong_keytab(krb_env: KerberosEnvironment) -> None:
    # The initiator keytab has no key for the service so the acceptor cannot
    # decrypt the ticket. Windows first replies with a KRB-ERROR so the
    # initiator retries, it only fails once the retried AP-REQ is rejected.
    c_cred = sspilib.UserCredential(
        krb_env.initiator_username,
        krb_env.initiator_password,
        protocol="Kerberos",
    )
    s_cred = sspilib.KeytabCredential(
        krb_env.acceptor_spn,
        krb_env.initiator_keytab,
        protocol="Kerberos",
        usage="accept",
    )

    c_ctx = sspilib.ClientSecurityContext(credential=c_cred, target_name=krb_env.acceptor_spn)
    s_ctx = sspilib.ServerSecurityContext(credential=s_cred)

    with pytest.raises(sr.WindowsError) as e:
        exchange(c_ctx, s_ctx)

    assert e.value.winerror == -2146893022  # SEC_E_WRONG_PRINCIPAL
