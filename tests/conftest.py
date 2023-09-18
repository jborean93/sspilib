# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import socket
import typing as t

import pytest

import sspi


@pytest.fixture()
def authenticated_contexts() -> tuple[sspi.InitiatorSecurityContext, sspi.AcceptorSecurityContext]:
    spn = f"host/{socket.gethostname()}"
    c_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_OUTBOUND)
    s_cred = sspi.acquire_credentials_handle(None, "Negotiate", sspi.CredentialUse.SECPKG_CRED_INBOUND)
    isc_req = (
        sspi.IscReq.ISC_REQ_ALLOCATE_MEMORY
        | sspi.IscReq.ISC_REQ_CONFIDENTIALITY
        | sspi.IscReq.ISC_REQ_INTEGRITY
        | sspi.IscReq.ISC_REQ_SEQUENCE_DETECT
        | sspi.IscReq.ISC_REQ_REPLAY_DETECT
    )
    asc_req = (
        sspi.AscReq.ASC_REQ_ALLOCATE_MEMORY
        | sspi.AscReq.ASC_REQ_CONFIDENTIALITY
        | sspi.AscReq.ASC_REQ_INTEGRITY
        | sspi.AscReq.ASC_REQ_SEQUENCE_DETECT
        | sspi.AscReq.ASC_REQ_REPLAY_DETECT
    )

    c_ctx = s_ctx = server_token = None
    while True:
        c_input_buffers = None
        if server_token:
            c_input_buffers = sspi.SecBufferDesc(
                [
                    sspi.SecBuffer(server_token, sspi.SecBufferType.SECBUFFER_TOKEN),
                ]
            )

        c_output_buffers = sspi.SecBufferDesc(
            [
                sspi.SecBuffer(None, sspi.SecBufferType.SECBUFFER_TOKEN),
            ]
        )
        c_ctx, c_status = sspi.initialize_security_context(
            credential=c_cred,
            context=c_ctx,
            target_name=spn,
            context_req=isc_req,
            target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
            input_buffers=c_input_buffers,
            output_buffers=c_output_buffers,
        )

        if c_output_buffers[0].count:
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
            s_ctx, s_status = sspi.accept_security_context(
                credential=s_cred,
                context=s_ctx,
                input_buffers=s_input_buffers,
                context_req=asc_req,
                target_data_rep=sspi.TargetDataRep.SECURITY_NATIVE_DREP,
                output_buffers=s_output_buffers,
            )

            if s_output_buffers[0].count:
                server_token = bytearray(s_output_buffers[0].data)
            elif s_status == sspi.NtStatus.SEC_E_OK:
                break
            else:
                raise ValueError(f"Expected SEC_E_OK but got {c_status.name}")

        elif c_status == sspi.NtStatus.SEC_E_OK:
            break
        else:
            raise ValueError(f"Expected SEC_E_OK but got {c_status.name}")

    return c_ctx, t.cast(sspi.AcceptorSecurityContext, s_ctx)
