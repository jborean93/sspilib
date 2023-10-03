# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os
import socket

import pytest

import sspilib.raw as sr


def test_sec_exchange_alloc_memory() -> None:
    spn = f"host/{socket.gethostname()}"

    auth_data = None
    server_package = "Negotiate"
    if os.name != "nt":
        # sspi-rs needs NTLM on the server with explicit creds
        auth_data = sr.WinNTAuthIdentity(
            username="user",
            password="pass",
        )
        server_package = "NTLM"

    c_cred = sr.acquire_credentials_handle(
        None,
        "NTLM",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=sr.IscReq.ISC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_cred = sr.acquire_credentials_handle(
        None,
        server_package,
        sr.CredentialUse.SECPKG_CRED_INBOUND,
        auth_data=auth_data,
    )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=sr.AscReq.ASC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=sr.IscReq.ISC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=sr.AscReq.ASC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)

    if os.name == "nt":
        assert s_res.status == sr.NtStatus.SEC_E_OK
    else:
        # https://github.com/Devolutions/sspi-rs/issues/167
        assert s_res.status == sr.NtStatus.SEC_I_COMPLETE_NEEDED
        sr.complete_auth_token(s_res.context, s_input_buffers)


def test_sec_exchange_prealloc_mem() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    auth_data = None
    server_package = "Negotiate"
    if os.name != "nt":
        # sspi-rs needs NTLM on the server with explicit creds
        auth_data = sr.WinNTAuthIdentity(
            username="user",
            password="pass",
        )
        server_package = "NTLM"

    c_cred = sr.acquire_credentials_handle(
        None,
        "NTLM",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_cred = sr.acquire_credentials_handle(
        None,
        server_package,
        sr.CredentialUse.SECPKG_CRED_INBOUND,
        auth_data=auth_data,
    )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)

    if os.name == "nt":
        assert s_res.status == sr.NtStatus.SEC_E_OK
    else:
        # https://github.com/Devolutions/sspi-rs/issues/167
        assert s_res.status == sr.NtStatus.SEC_I_COMPLETE_NEEDED
        sr.complete_auth_token(s_res.context, s_input_buffers)


# https://github.com/Devolutions/sspi-rs/issues/172
@pytest.mark.skipif(os.name != "nt", reason="Seems like sspi-rs doesn't validate the credentials")
def test_invalid_credential() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    invalid_cred = sr.WinNTAuthIdentity(username="invalid", password="invalid")
    c_cred = sr.acquire_credentials_handle(
        None,
        "NTLM",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=invalid_cred,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    if os.name == "nt":
        s_cred = sr.acquire_credentials_handle(
            None,
            "Negotiate",
            sr.CredentialUse.SECPKG_CRED_INBOUND,
        )[0]
    else:
        s_cred = sr.acquire_credentials_handle(
            None,
            "NTLM",
            sr.CredentialUse.SECPKG_CRED_INBOUND,
            auth_data=sr.WinNTAuthIdentity(username="invalid", password="other"),
        )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    with pytest.raises(sr.WindowsError) as e:
        sr.accept_security_context(
            credential=s_cred,
            context=s_res.context,
            input_buffers=s_input_buffers,
            context_req=0,
            target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
            output_buffers=s_output_buffers,
        )

    assert e.value.winerror == -2146893044  # SEC_E_LOGON_DENIED


def test_sec_exchange_with_channel_binding() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)
    channel_bindings = sr.SecChannelBindings(
        application_data=b"tls-server-end-point:" + (b"\x00" * 32),
    ).get_sec_buffer_copy()

    auth_data = None
    server_package = "Negotiate"
    if os.name != "nt":
        # sspi-rs needs NTLM on the server with explicit creds
        auth_data = sr.WinNTAuthIdentity(
            username="user",
            password="pass",
        )
        server_package = "NTLM"

    c_cred = sr.acquire_credentials_handle(
        None,
        "NTLM",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_input_buffers = sr.SecBufferDesc([channel_bindings])
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_cred = sr.acquire_credentials_handle(
        None,
        server_package,
        sr.CredentialUse.SECPKG_CRED_INBOUND,
        auth_data=auth_data,
    )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)

    if os.name == "nt":
        assert s_res.status == sr.NtStatus.SEC_E_OK
    else:
        # https://github.com/Devolutions/sspi-rs/issues/167
        assert s_res.status == sr.NtStatus.SEC_I_COMPLETE_NEEDED
        sr.complete_auth_token(s_res.context, s_input_buffers)


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not play well in this scenario")
def test_sec_exchange_allowed_package_list() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    auth_data = sr.WinNTAuthIdentity(package_list="NTLM")
    c_cred = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_cred = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_INBOUND,
    )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=None,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_E_OK


@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not play well in this scenario")
def test_sec_exchange_with_negotiate_restricted_package() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    auth_data = sr.WinNTAuthIdentity(package_list="!Kerberos")
    c_cred = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_cred = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_INBOUND,
    )[0]
    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert c_res.status == sr.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sr.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sr.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(c_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sr.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sr.AcceptContextResult)
    assert isinstance(s_res.context, sr.CtxtHandle)
    assert isinstance(s_res.attributes, sr.AscRet)
    assert isinstance(s_res.expiry, int)
    assert isinstance(s_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_E_OK

    c_input_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(s_output_buffers[0].dangerous_get_view(), sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(buffer, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sr.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sr.InitializeContextResult)
    assert isinstance(c_res.context, sr.CtxtHandle)
    assert isinstance(c_res.attributes, sr.IscRet)
    assert isinstance(c_res.expiry, int)
    assert isinstance(c_res.status, sr.NtStatus)
    assert s_res.status == sr.NtStatus.SEC_E_OK

    assert c_output_buffers[0].count == 0
    assert c_output_buffers[0].data == b""


# https://github.com/Devolutions/sspi-rs/issues/171
@pytest.mark.skipif(os.name != "nt", reason="sspi-rs does not support this scenario yet")
def test_fail_with_negotiate_and_no_available_packages() -> None:
    spn = f"host/{socket.gethostname()}"

    auth_data = sr.WinNTAuthIdentity(package_list="NegoExtender")
    c_cred = sr.acquire_credentials_handle(
        None,
        "Negotiate",
        sr.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )[0]
    c_output_buffers = sr.SecBufferDesc(
        [
            sr.SecBuffer(None, sr.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    with pytest.raises(sr.WindowsError) as e:
        sr.initialize_security_context(
            credential=c_cred,
            context=None,
            target_name=spn,
            context_req=sr.IscReq.ISC_REQ_ALLOCATE_MEMORY,
            target_data_rep=sr.TargetDataRep.SECURITY_NATIVE_DREP,
            input_buffers=None,
            output_buffers=c_output_buffers,
        )

    assert e.value.winerror == -2146893042  # SEC_E_NO_CREDENTIALS
