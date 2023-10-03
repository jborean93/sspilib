# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from ._security_buffer cimport PSecBufferDesc, SecBufferDesc
from ._security_context cimport CtxtHandle
from ._win32_types cimport *


cdef extern from "python_sspi.h":
    unsigned int _KERB_WRAP_NO_ENCRYPT "KERB_WRAP_NO_ENCRYPT"

    unsigned int _SECQOP_WRAP_NO_ENCRYPT "SECQOP_WRAP_NO_ENCRYPT"
    unsigned int _SECQOP_WRAP_OOB_DATA "SECQOP_WRAP_OOB_DATA"

    # https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
    SECURITY_STATUS DecryptMessage(
        PCtxtHandle    phContext,
        PSecBufferDesc pMessage,
        unsigned int  MessageSeqNo,
        unsigned int  *pfQOP
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general
    SECURITY_STATUS EncryptMessage(
        PCtxtHandle    phContext,
        unsigned int  fQOP,
        PSecBufferDesc pMessage,
        unsigned int  MessageSeqNo
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-makesignature
    SECURITY_STATUS MakeSignature(
        PCtxtHandle    phContext,
        unsigned int  fQOP,
        PSecBufferDesc pMessage,
        unsigned int  MessageSeqNo
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-verifysignature
    SECURITY_STATUS VerifySignature(
        PCtxtHandle    phContext,
        PSecBufferDesc pMessage,
        unsigned int  MessageSeqNo,
        unsigned int  *pfQOP
    ) nogil


class QopFlags(enum.IntFlag):
    KERB_WRAP_NO_ENCRYPT = _KERB_WRAP_NO_ENCRYPT
    SECQOP_WRAP_NO_ENCRYPT = _SECQOP_WRAP_NO_ENCRYPT
    SECQOP_WRAP_OOB_DATA = _SECQOP_WRAP_OOB_DATA

def decrypt_message(
    CtxtHandle context not None,
    SecBufferDesc message not None,
    unsigned int seq_no,
) -> int:
    cdef unsigned int qop = 0
    with nogil:
        res = DecryptMessage(
            &context.raw,
            &message.raw,
            seq_no,
            &qop
        )

    if res:
        PyErr_SetFromWindowsErr(res)

    message.sync_buffers()

    return qop

def encrypt_message(
    CtxtHandle context not None,
    unsigned int qop,
    SecBufferDesc message not None,
    unsigned int seq_no,
) -> None:
    with nogil:
        res = EncryptMessage(
            &context.raw,
            qop,
            &message.raw,
            seq_no,
        )

    if res:
        PyErr_SetFromWindowsErr(res)

    message.sync_buffers()

def make_signature(
    CtxtHandle context not None,
    unsigned int qop,
    SecBufferDesc message not None,
    unsigned int seq_no,
) -> None:
    with nogil:
        res = MakeSignature(
            &context.raw,
            qop,
            &message.raw,
            seq_no,
        )

    if res:
        PyErr_SetFromWindowsErr(res)

    message.sync_buffers()

def verify_signature(
    CtxtHandle context not None,
    SecBufferDesc message not None,
    unsigned int seq_no,
) -> int:
    cdef unsigned int qop = 0
    with nogil:
        res = VerifySignature(
            &context.raw,
            &message.raw,
            seq_no,
            &qop
        )

    if res:
        PyErr_SetFromWindowsErr(res)

    message.sync_buffers()

    return qop
