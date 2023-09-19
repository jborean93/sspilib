# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import socket

import pytest

import sspi


def test_sec_exchange_default_cred() -> None:
    spn = f"host/{socket.gethostname()}"

    c_cred = sspi.acquire_credentials_handle(None, "NTLM", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=sspi.IscReq.ISC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=sspi.AscReq.ASC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=sspi.IscReq.ISC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=sspi.AscReq.ASC_REQ_ALLOCATE_MEMORY,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=None,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_E_OK


def test_sec_exchange_prealloc_mem() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    c_cred = sspi.acquire_credentials_handle(None, "NTLM", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=None,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_E_OK


def test_invalid_credential() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    invalid_cred = sspi.WinNTAuthIdentity(username="invalid", password="invalid")
    c_cred = sspi.acquire_credentials_handle(
        None,
        "NTLM",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=invalid_cred,
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    with pytest.raises(WindowsError) as e:
        sspi.accept_security_context(
            credential=s_cred,
            context=s_res.context,
            input_buffers=s_input_buffers,
            context_req=0,
            target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
            output_buffers=None,
        )

    assert e.value.winerror == -2146893044  # SEC_E_LOGON_DENIED


def test_sec_exchange_with_channel_binding() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)
    channel_bindings = sspi.SecChannelBindings(
        application_data=b"tls-server-end-point:" + (b"\x00" * 32),
    ).get_sec_buffer_copy()

    c_cred = sspi.acquire_credentials_handle(None, "NTLM", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    c_input_buffers = sspi.SecBufferDesc([channel_bindings])
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
            channel_bindings,
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=None,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_E_OK


def test_sec_exchange_allowed_package_list() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    auth_data = sspi.WinNTAuthIdentity(package_list="NTLM")
    c_cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=None,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_E_OK


def test_sec_exchange_with_negotiate_restricted_package() -> None:
    spn = f"host/{socket.gethostname()}"
    buffer = bytearray(4096)

    auth_data = sspi.WinNTAuthIdentity(package_list="!Kerberos")
    c_cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=None,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=None,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=None,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert s_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert s_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert isinstance(c_res.context.expiry, int)
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_I_CONTINUE_NEEDED

    assert c_output_buffers[0].buffer_type == sspi.SecBufferType.SECBUFFER_TOKEN
    assert c_output_buffers[0].buffer_flags == sspi.SecBufferFlags.SECBUFFER_NONE

    s_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(c_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    s_res = sspi.accept_security_context(
        credential=s_cred,
        context=s_res.context,
        input_buffers=s_input_buffers,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        output_buffers=s_output_buffers,
    )
    assert isinstance(s_res, sspi.AcceptContextResult)
    assert isinstance(s_res.context, sspi.AcceptorSecurityContext)
    assert isinstance(s_res.context.context_attr, sspi.AscRet)
    assert s_res.context.expiry > 0
    assert isinstance(s_res.result, sspi.NtStatus)
    assert s_res.result == sspi.NtStatus.SEC_E_OK

    c_input_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(s_output_buffers[0].dangerous_get_view(), sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(buffer, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    c_res = sspi.initialize_security_context(
        credential=c_cred,
        context=c_res.context,
        target_name=spn,
        context_req=0,
        target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
        input_buffers=c_input_buffers,
        output_buffers=c_output_buffers,
    )
    assert isinstance(c_res, sspi.InitializeContextResult)
    assert isinstance(c_res.context, sspi.InitiatorSecurityContext)
    assert isinstance(c_res.context.context_attr, sspi.IscRet)
    assert c_res.context.expiry > 0
    assert isinstance(c_res.result, sspi.NtStatus)
    assert c_res.result == sspi.NtStatus.SEC_E_OK

    assert c_output_buffers[0].count == 0
    assert c_output_buffers[0].data == b""


def test_fail_with_negotiate_and_no_available_packages() -> None:
    spn = f"host/{socket.gethostname()}"

    auth_data = sspi.WinNTAuthIdentity(package_list="NegoExtender")
    c_cred = sspi.acquire_credentials_handle(
        None,
        "Negotiate",
        sspi.CredentialUse.SECPKG_CRED_OUTBOUND,
        auth_data=auth_data,
    )
    c_output_buffers = sspi.SecBufferDesc(
        [
            sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_TOKEN),
        ]
    )
    with pytest.raises(WindowsError) as e:
        sspi.initialize_security_context(
            credential=c_cred,
            context=None,
            target_name=spn,
            context_req=sspi.IscReq.ISC_REQ_ALLOCATE_MEMORY,
            target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
            input_buffers=None,
            output_buffers=c_output_buffers,
        )

    assert e.value.winerror == -2146893042  # SEC_E_NO_CREDENTIALS
