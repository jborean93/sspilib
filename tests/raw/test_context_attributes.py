# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os

import pytest

import sspilib.raw as sr


# https://github.com/Devolutions/sspi-rs/issues/169
@pytest.mark.skipif(os.name != "nt", reason="SECPKG_ATTR_NAMES is not implemented in sspi-rs")
def test_query_names(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    c_actual = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextNames)
    assert isinstance(c_actual, sr.SecPkgContextNames)
    assert isinstance(c_actual.username, str)

    s_actual = sr.query_context_attributes(authenticated_contexts[1], sr.SecPkgContextNames)
    assert isinstance(s_actual, sr.SecPkgContextNames)
    assert isinstance(s_actual.username, str)

    assert c_actual.username == s_actual.username
    assert repr(c_actual) == repr(s_actual)


def test_query_package_info(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    c_actual = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextPackageInfo)
    assert isinstance(c_actual, sr.SecPkgContextPackageInfo)
    assert isinstance(c_actual.capabilities, sr.SecurityPackageCapability)
    assert isinstance(c_actual.version, int)
    assert isinstance(c_actual.rpcid, int)
    assert isinstance(c_actual.max_token, int)
    assert isinstance(c_actual.name, str)
    assert isinstance(c_actual.comment, str)

    s_actual = sr.query_context_attributes(authenticated_contexts[1], sr.SecPkgContextPackageInfo)
    assert isinstance(s_actual, sr.SecPkgContextPackageInfo)
    assert isinstance(s_actual.capabilities, sr.SecurityPackageCapability)
    assert isinstance(s_actual.version, int)
    assert isinstance(s_actual.rpcid, int)
    assert isinstance(s_actual.max_token, int)
    assert isinstance(s_actual.name, str)
    assert isinstance(s_actual.comment, str)

    assert c_actual.capabilities == s_actual.capabilities
    assert c_actual.version == s_actual.version
    assert c_actual.rpcid == s_actual.rpcid
    assert c_actual.max_token == s_actual.max_token
    assert c_actual.name == s_actual.name
    assert c_actual.comment == s_actual.comment
    assert repr(c_actual) == repr(s_actual)


# https://github.com/Devolutions/sspi-rs/issues/168
@pytest.mark.skipif(os.name != "nt", reason="SECPKG_ATTR_SESSION_KEY is not implemented in sspi-rs")
def test_query_session_keys(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    c_actual = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSessionKey)
    assert isinstance(c_actual, sr.SecPkgContextSessionKey)
    assert isinstance(c_actual.session_key, bytes)

    s_actual = sr.query_context_attributes(authenticated_contexts[1], sr.SecPkgContextSessionKey)
    assert isinstance(s_actual, sr.SecPkgContextSessionKey)
    assert isinstance(s_actual.session_key, bytes)

    assert c_actual.session_key == s_actual.session_key
    assert repr(c_actual) == repr(s_actual)


def test_query_sizes(
    authenticated_contexts: tuple[sr.CtxtHandle, sr.CtxtHandle],
) -> None:
    c_actual = sr.query_context_attributes(authenticated_contexts[0], sr.SecPkgContextSizes)
    assert isinstance(c_actual, sr.SecPkgContextSizes)
    assert isinstance(c_actual.max_signature, int)
    assert isinstance(c_actual.max_token, int)
    assert isinstance(c_actual.block_size, int)
    assert isinstance(c_actual.security_trailer, int)

    s_actual = sr.query_context_attributes(authenticated_contexts[1], sr.SecPkgContextSizes)
    assert isinstance(s_actual, sr.SecPkgContextSizes)
    assert isinstance(s_actual.max_signature, int)
    assert isinstance(s_actual.max_token, int)
    assert isinstance(s_actual.block_size, int)
    assert isinstance(s_actual.security_trailer, int)

    assert c_actual.max_signature == s_actual.max_signature
    assert c_actual.max_token == s_actual.max_token
    assert c_actual.block_size == s_actual.block_size
    assert c_actual.security_trailer == s_actual.security_trailer
    assert repr(c_actual) == repr(s_actual)
