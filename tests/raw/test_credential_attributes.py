# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os

import sspilib.raw as sr


def test_set_kdc_proxy_default() -> None:
    kdc_proxy = sr.SecPkgCredKdcProxySettings()
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sr.KdcProxySettingsFlags.KDX_PROXY_SETTINGS_FLAGS_NONE
    assert kdc_proxy.proxy_server is None
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=0, proxy_server=None)"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    auth_data = None
    if os.name != "nt":
        auth_data = sr.WinNTAuthIdentity(username="user", password="pass")
    cred = sr.acquire_credentials_handle(
        None,
        "Kerberos",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    sr.set_credentials_attributes(cred, kdc_proxy)


def test_set_kdc_proxy_flags() -> None:
    kdc_proxy = sr.SecPkgCredKdcProxySettings(flags=sr.KdcProxySettingsFlags.KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY)
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sr.KdcProxySettingsFlags.KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY
    assert kdc_proxy.proxy_server is None
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=1, proxy_server=None)"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    auth_data = None
    if os.name != "nt":
        auth_data = sr.WinNTAuthIdentity(username="user", password="pass")
    cred = sr.acquire_credentials_handle(
        None,
        "Kerberos",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    sr.set_credentials_attributes(cred, kdc_proxy)


def test_set_kdc_proxy_server() -> None:
    # Test the length calcs work with NULL and surrogate pairs
    kdc_proxy = sr.SecPkgCredKdcProxySettings(proxy_server="kdc.\U0001f4a0.com:443:kdc\u0000proxy")
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sr.KdcProxySettingsFlags.KDX_PROXY_SETTINGS_FLAGS_NONE
    assert kdc_proxy.proxy_server == "kdc.\U0001f4a0.com:443:kdc\u0000proxy"
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=0, proxy_server='kdc.\U0001f4a0.com:443:kdc\\x00proxy')"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    auth_data = None
    if os.name != "nt":
        auth_data = sr.WinNTAuthIdentity(username="user", password="pass")
    cred = sr.acquire_credentials_handle(
        None,
        "Kerberos",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    sr.set_credentials_attributes(cred, kdc_proxy)
