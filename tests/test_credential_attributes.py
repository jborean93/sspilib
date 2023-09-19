# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import sspi


def test_set_kdc_proxy_default() -> None:
    kdc_proxy = sspi.SecPkgCredKdcProxySettings()
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sspi.KdcProxySettingsFlags.KDX_PROXY_SETTINGS_FLAGS_NONE
    assert kdc_proxy.proxy_server is None
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=0, proxy_server=None)"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    cred = sspi.acquire_credentials_handle(None, "Kerberos", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    sspi.set_credentials_attributes(cred, kdc_proxy)


def test_set_kdc_proxy_flags() -> None:
    kdc_proxy = sspi.SecPkgCredKdcProxySettings(flags=sspi.KdcProxySettingsFlags.KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY)
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sspi.KdcProxySettingsFlags.KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY
    assert kdc_proxy.proxy_server is None
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=1, proxy_server=None)"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    cred = sspi.acquire_credentials_handle(None, "Kerberos", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    sspi.set_credentials_attributes(cred, kdc_proxy)


def test_set_kdc_proxy_server() -> None:
    # Test the length calcs work with NULL and surrogate pairs
    kdc_proxy = sspi.SecPkgCredKdcProxySettings(proxy_server="kdc.\U0001F4A0.com:443:kdc\u0000proxy")
    assert kdc_proxy.version == 1
    assert kdc_proxy.flags == sspi.KdcProxySettingsFlags.KDX_PROXY_SETTINGS_FLAGS_NONE
    assert kdc_proxy.proxy_server == "kdc.\U0001F4A0.com:443:kdc\u0000proxy"
    assert repr(kdc_proxy) == "SecPkgCredKdcProxySettings(flags=0, proxy_server='kdc.\U0001F4A0.com:443:kdc\\x00proxy')"

    # While we can't verify it we can at least make sure it doesn't fail to set.
    cred = sspi.acquire_credentials_handle(None, "Kerberos", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    sspi.set_credentials_attributes(cred, kdc_proxy)
