# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._security_buffer cimport PSecBufferDesc, SecBufferDesc
from sspi._security_context cimport SecurityContext
from sspi._win32_types cimport *


cdef extern from "NTSecAPI.h":
    unsigned long _KERB_WRAP_NO_ENCRYPT "KERB_WRAP_NO_ENCRYPT"

cdef extern from "Security.h":
    unsigned long _SECQOP_WRAP_NO_ENCRYPT "SECQOP_WRAP_NO_ENCRYPT"
    unsigned long _SECQOP_WRAP_OOB_DATA "SECQOP_WRAP_OOB_DATA"

    # https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
    SECURITY_STATUS DecryptMessage(
        PCtxtHandle    phContext,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo,
        unsigned long  *pfQOP
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general
    SECURITY_STATUS EncryptMessage(
        PCtxtHandle    phContext,
        unsigned long  fQOP,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-makesignature
    SECURITY_STATUS MakeSignature(
        PCtxtHandle    phContext,
        unsigned long  fQOP,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-verifysignature
    SECURITY_STATUS VerifySignature(
        PCtxtHandle    phContext,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo,
        unsigned long  *pfQOP
    ) nogil


class QopFlags(enum.IntFlag):
    KERB_WRAP_NO_ENCRYPT = _KERB_WRAP_NO_ENCRYPT
    SECQOP_WRAP_NO_ENCRYPT = _SECQOP_WRAP_NO_ENCRYPT
    SECQOP_WRAP_OOB_DATA = _SECQOP_WRAP_OOB_DATA

def decrypt_message(
    SecurityContext context not None,
    SecBufferDesc message not None,
    unsigned long seq_no,
) -> int:
    cdef unsigned long qop = 0
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
    SecurityContext context not None,
    unsigned long qop,
    SecBufferDesc message not None,
    unsigned long seq_no,
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
    SecurityContext context not None,
    unsigned long qop,
    SecBufferDesc message not None,
    unsigned long seq_no,
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
    SecurityContext context not None,
    SecBufferDesc message not None,
    unsigned long seq_no,
) -> int:
    cdef unsigned long qop = 0
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
