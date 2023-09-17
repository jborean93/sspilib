# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pytest

import sspi


def test_get_outbound_with_default_context() -> None:
    cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
    )
    assert isinstance(cred, sspi.Credential)
    assert cred.expiry > 0


def test_get_inbound_with_default_context() -> None:
    cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_INBOUND,
    )
    assert isinstance(cred, sspi.Credential)
    assert cred.expiry > 0


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
            "user\U0001F4A9",
            "DOMAIN\U0001F4A9",
            "DOMAIN\U0001F4A9\\user\U0001F4A9",
            "WinNTAuthIdentity(username='user\U0001F4A9', domain='DOMAIN\U0001F4A9', password='pass', flags=2, package_list=None)",
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
    auth_identity = sspi.WinNTAuthIdentity(
        username=username,
        domain=domain,
        password=password,
    )
    assert auth_identity.username == username
    assert auth_identity.domain == domain
    assert auth_identity.password == password
    assert auth_identity.package_list is None
    assert auth_identity.flags == sspi.WinNTAuthFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE
    assert str(auth_identity) == expected_str
    assert repr(auth_identity) == expected_repr

    cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_identity,
    )
    assert isinstance(cred, sspi.Credential)
    assert cred.expiry > 0


def test_get_cred_with_explicit_credentials_package_list() -> None:
    auth_identity = sspi.WinNTAuthIdentity(
        username="username",
        password="DummyPasswordHere",
        package_list="!kerberos",
    )
    assert auth_identity.package_list == "!kerberos"
    assert auth_identity.flags == sspi.WinNTAuthFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE

    cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_identity,
    )
    assert isinstance(cred, sspi.Credential)
    assert cred.expiry > 0


def test_get_credential_with_principal() -> None:
    cred = sspi.acquire_credentials_handle(
        "Principal",
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
    )
    assert isinstance(cred, sspi.Credential)
    assert cred.expiry > 0


def test_fail_with_invalid_package_name() -> None:
    with pytest.raises(WindowsError) as e:
        sspi.acquire_credentials_handle(None, "Invalid", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)

    assert e.value.winerror == -2146893051  # SEC_E_SECPKG_NOT_FOUND
