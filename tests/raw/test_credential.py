# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os

import pytest

import sspilib.raw as sr


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support implicit creds outside Windows")
def test_get_outbound_with_default_context() -> None:
    res = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
    )
    assert isinstance(res, sr.AcquireCredentialsResult)
    assert isinstance(res.credential, sr.CredHandle)
    assert isinstance(res.expiry, int)


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support implicit creds outside Windows")
def test_get_inbound_with_default_context() -> None:
    res = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_INBOUND,
    )
    assert isinstance(res, sr.AcquireCredentialsResult)
    assert isinstance(res.credential, sr.CredHandle)
    assert isinstance(res.expiry, int)


@pytest.mark.parametrize(
    ["username", "domain", "expected_str", "expected_repr"],
    [
        (
            "username",
            None,
            "username",
            "WinNTAuthIdentity(username='username', domain=None, password='pass', flags=2, package_list=None)",
        ),
        (
            "username@DOMAIN.COM",
            None,
            "username@DOMAIN.COM",
            "WinNTAuthIdentity(username='username@DOMAIN.COM', domain=None, password='pass', flags=2, package_list=None)",
        ),
        (
            "username",
            "DOMAIN",
            "DOMAIN\\username",
            "WinNTAuthIdentity(username='username', domain='DOMAIN', password='pass', flags=2, package_list=None)",
        ),
        (
            "user\U0001f4a9",
            "DOMAIN\U0001f4a9",
            "DOMAIN\U0001f4a9\\user\U0001f4a9",
            "WinNTAuthIdentity(username='user\U0001f4a9', domain='DOMAIN\U0001f4a9', password='pass', flags=2, package_list=None)",
        ),
    ],
    ids=[
        "username_only",
        "username_domain_upn",
        "username_domain_netbios",
        "unicode_surrogates",
    ],
)
def test_get_cred_with_explicit_credentials(
    username: str | None,
    domain: str | None,
    expected_str: str,
    expected_repr: str,
) -> None:
    password = "pass"
    auth_identity = sr.WinNTAuthIdentity(
        username=username,
        domain=domain,
        password=password,
    )
    assert auth_identity.username == username
    assert auth_identity.domain == domain
    assert auth_identity.password == password
    assert auth_identity.package_list is None
    assert auth_identity.flags == sr.WinNTAuthFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE
    assert str(auth_identity) == expected_str
    assert repr(auth_identity) == expected_repr

    res = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_identity,
    )
    assert isinstance(res, sr.AcquireCredentialsResult)
    assert isinstance(res.credential, sr.CredHandle)
    assert isinstance(res.expiry, int)


def test_get_cred_with_explicit_credentials_package_list() -> None:
    auth_identity = sr.WinNTAuthIdentity(
        username="username",
        password="DummyPasswordHere",
        package_list="!kerberos",
    )
    assert auth_identity.package_list == "!kerberos"
    assert auth_identity.flags == sr.WinNTAuthFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE

    res = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_identity,
    )
    assert isinstance(res, sr.AcquireCredentialsResult)
    assert isinstance(res.credential, sr.CredHandle)
    assert isinstance(res.expiry, int)


def test_get_credential_with_principal() -> None:
    auth_data = None
    if os.name != "nt":
        # sspi-rs needs explicit creds for this to work.
        auth_data = sr.WinNTAuthIdentity(username="user", password="pass")

    res = sr.acquire_credentials_handle(
        "Principal",
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )
    assert isinstance(res, sr.AcquireCredentialsResult)
    assert isinstance(res.credential, sr.CredHandle)
    assert isinstance(res.expiry, int)


def test_fail_with_invalid_package_name() -> None:
    with pytest.raises(sr.WindowsError) as e:
        sr.acquire_credentials_handle(None, "Invalid", sr.CredentialUse.SECPKG_CRED_OUTBOUND)

    if os.name == "nt":
        assert e.value.winerror == -2146893051  # SEC_E_SECPKG_NOT_FOUND
    else:
        # https://github.com/Devolutions/sspi-rs/issues/170
        assert e.value.winerror == -2146892963  # SEC_E_INVALID_PARAMETER


@pytest.mark.parametrize(
    ["username", "domain", "package_list", "expected_str", "expected_repr"],
    [
        (
            "username",
            None,
            None,
            "WinNTAuthIdentityPackedCredential d587aae8-f78f-4455-a112-c934beee7ce1 for username",
            "WinNTAuthIdentityPackedCredential(credential_type=UUID('d587aae8-f78f-4455-a112-c934beee7ce1'), credential=b'foo', username='username', domain=None, flags=2, package_list=None)",
        ),
        (
            "username@DOMAIN.COM",
            None,
            None,
            "WinNTAuthIdentityPackedCredential d587aae8-f78f-4455-a112-c934beee7ce1 for username@DOMAIN.COM",
            "WinNTAuthIdentityPackedCredential(credential_type=UUID('d587aae8-f78f-4455-a112-c934beee7ce1'), credential=b'foo', username='username@DOMAIN.COM', domain=None, flags=2, package_list=None)",
        ),
        (
            "username",
            "DOMAIN",
            None,
            "WinNTAuthIdentityPackedCredential d587aae8-f78f-4455-a112-c934beee7ce1 for DOMAIN\\username",
            "WinNTAuthIdentityPackedCredential(credential_type=UUID('d587aae8-f78f-4455-a112-c934beee7ce1'), credential=b'foo', username='username', domain='DOMAIN', flags=2, package_list=None)",
        ),
        (
            "user\U0001f4a9",
            "DOMAIN\U0001f4a9",
            None,
            "WinNTAuthIdentityPackedCredential d587aae8-f78f-4455-a112-c934beee7ce1 for DOMAIN\U0001f4a9\\user\U0001f4a9",
            "WinNTAuthIdentityPackedCredential(credential_type=UUID('d587aae8-f78f-4455-a112-c934beee7ce1'), credential=b'foo', username='user\U0001f4a9', domain='DOMAIN\U0001f4a9', flags=2, package_list=None)",
        ),
        (
            None,
            None,
            "kerberos,!ntlm",
            "WinNTAuthIdentityPackedCredential d587aae8-f78f-4455-a112-c934beee7ce1",
            "WinNTAuthIdentityPackedCredential(credential_type=UUID('d587aae8-f78f-4455-a112-c934beee7ce1'), credential=b'foo', username=None, domain=None, flags=2, package_list='kerberos,!ntlm')",
        ),
    ],
    ids=[
        "username_only",
        "username_domain_upn",
        "username_domain_netbios",
        "unicode_surrogates",
        "package_list_no_username",
    ],
)
def test_win_nt_auth_identity_packed_credential_packing(
    username: str | None,
    domain: str | None,
    package_list: str | None,
    expected_str: str,
    expected_repr: str,
) -> None:
    auth_identity = sr.WinNTAuthIdentityPackedCredential(
        sr.WinNTAuthCredentialType.SEC_WINNT_AUTH_DATA_TYPE_KEYTAB,
        b"foo",
        username=username,
        domain=domain,
        package_list=package_list,
    )

    assert auth_identity.credential_type == sr.WinNTAuthCredentialType.SEC_WINNT_AUTH_DATA_TYPE_KEYTAB
    assert auth_identity.credential == b"foo"
    assert auth_identity.username == username
    assert auth_identity.domain == domain
    assert auth_identity.package_list == package_list
    assert auth_identity.flags == sr.WinNTAuthFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE
    assert str(auth_identity) == expected_str, f"'{auth_identity}' != '{expected_str}'"
    assert repr(auth_identity) == expected_repr, f"'{auth_identity!r}' != '{expected_repr}'"
