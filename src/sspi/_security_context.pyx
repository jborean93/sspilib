# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._credential cimport Credential
from sspi._security_buffer cimport PSecBufferDesc, SecBufferDesc
from sspi._text cimport WideCharString
from sspi._win32_types cimport *


cdef extern from "Security.h":
    unsigned long _SECURITY_NATIVE_DREP "SECURITY_NATIVE_DREP"
    unsigned long _SECURITY_NETWORK_DREP "SECURITY_NETWORK_DREP"

    unsigned long ISC_REQ_DELEGATE "_ISC_REQ_DELEGATE"
    unsigned long ISC_REQ_MUTUAL_AUTH "_ISC_REQ_MUTUAL_AUTH"
    unsigned long ISC_REQ_REPLAY_DETECT "_ISC_REQ_REPLAY_DETECT"
    unsigned long ISC_REQ_SEQUENCE_DETECT "_ISC_REQ_SEQUENCE_DETECT"
    unsigned long ISC_REQ_CONFIDENTIALITY "_ISC_REQ_CONFIDENTIALITY"
    unsigned long ISC_REQ_USE_SESSION_KEY "_ISC_REQ_USE_SESSION_KEY"
    unsigned long ISC_REQ_PROMPT_FOR_CREDS "_ISC_REQ_PROMPT_FOR_CREDS"
    unsigned long ISC_REQ_USE_SUPPLIED_CREDS "_ISC_REQ_USE_SUPPLIED_CREDS"
    unsigned long ISC_REQ_ALLOCATE_MEMORY "_ISC_REQ_ALLOCATE_MEMORY"
    unsigned long ISC_REQ_USE_DCE_STYLE "_ISC_REQ_USE_DCE_STYLE"
    unsigned long ISC_REQ_DATAGRAM "_ISC_REQ_DATAGRAM"
    unsigned long ISC_REQ_CONNECTION "_ISC_REQ_CONNECTION"
    unsigned long ISC_REQ_CALL_LEVEL "_ISC_REQ_CALL_LEVEL"
    unsigned long ISC_REQ_FRAGMENT_SUPPLIED "_ISC_REQ_FRAGMENT_SUPPLIED"
    unsigned long ISC_REQ_EXTENDED_ERROR "_ISC_REQ_EXTENDED_ERROR"
    unsigned long ISC_REQ_STREAM "_ISC_REQ_STREAM"
    unsigned long ISC_REQ_INTEGRITY "_ISC_REQ_INTEGRITY"
    unsigned long ISC_REQ_IDENTIFY "_ISC_REQ_IDENTIFY"
    unsigned long ISC_REQ_NULL_SESSION "_ISC_REQ_NULL_SESSION"
    unsigned long ISC_REQ_MANUAL_CRED_VALIDATION "_ISC_REQ_MANUAL_CRED_VALIDATION"
    unsigned long ISC_REQ_RESERVED1 "_ISC_REQ_RESERVED1"
    unsigned long ISC_REQ_FRAGMENT_TO_FIT "_ISC_REQ_FRAGMENT_TO_FIT"
    unsigned long ISC_REQ_FORWARD_CREDENTIALS "_ISC_REQ_FORWARD_CREDENTIALS"
    unsigned long ISC_REQ_NO_INTEGRITY "_ISC_REQ_NO_INTEGRITY"
    unsigned long ISC_REQ_USE_HTTP_STYLE "_ISC_REQ_USE_HTTP_STYLE"
    unsigned long ISC_REQ_UNVERIFIED_TARGET_NAME "_ISC_REQ_UNVERIFIED_TARGET_NAME"
    unsigned long ISC_REQ_CONFIDENTIALITY_ONLY "_ISC_REQ_CONFIDENTIALITY_ONLY"

    unsigned long ISC_RET_DELEGATE "_ISC_RET_DELEGATE"
    unsigned long ISC_RET_MUTUAL_AUTH "_ISC_RET_MUTUAL_AUTH"
    unsigned long ISC_RET_REPLAY_DETECT "_ISC_RET_REPLAY_DETECT"
    unsigned long ISC_RET_SEQUENCE_DETECT "_ISC_RET_SEQUENCE_DETECT"
    unsigned long ISC_RET_CONFIDENTIALITY "_ISC_RET_CONFIDENTIALITY"
    unsigned long ISC_RET_USE_SESSION_KEY "_ISC_RET_USE_SESSION_KEY"
    unsigned long ISC_RET_USED_COLLECTED_CREDS "_ISC_RET_USED_COLLECTED_CREDS"
    unsigned long ISC_RET_USED_SUPPLIED_CREDS "_ISC_RET_USED_SUPPLIED_CREDS"
    unsigned long ISC_RET_ALLOCATED_MEMORY "_ISC_RET_ALLOCATED_MEMORY"
    unsigned long ISC_RET_USED_DCE_STYLE "_ISC_RET_USED_DCE_STYLE"
    unsigned long ISC_RET_DATAGRAM "_ISC_RET_DATAGRAM"
    unsigned long ISC_RET_CONNECTION "_ISC_RET_CONNECTION"
    unsigned long ISC_RET_INTERMEDIATE_RETURN "_ISC_RET_INTERMEDIATE_RETURN"
    unsigned long ISC_RET_CALL_LEVEL "_ISC_RET_CALL_LEVEL"
    unsigned long ISC_RET_EXTENDED_ERROR "_ISC_RET_EXTENDED_ERROR"
    unsigned long ISC_RET_STREAM "_ISC_RET_STREAM"
    unsigned long ISC_RET_INTEGRITY "_ISC_RET_INTEGRITY"
    unsigned long ISC_RET_IDENTIFY "_ISC_RET_IDENTIFY"
    unsigned long ISC_RET_NULL_SESSION "_ISC_RET_NULL_SESSION"
    unsigned long ISC_RET_MANUAL_CRED_VALIDATION "_ISC_RET_MANUAL_CRED_VALIDATION"
    unsigned long ISC_RET_RESERVED1 "_ISC_RET_RESERVED1"
    unsigned long ISC_RET_FRAGMENT_ONLY "_ISC_RET_FRAGMENT_ONLY"
    unsigned long ISC_RET_FORWARD_CREDENTIALS "_ISC_RET_FORWARD_CREDENTIALS"
    unsigned long ISC_RET_USED_HTTP_STYLE "_ISC_RET_USED_HTTP_STYLE"
    unsigned long ISC_RET_NO_ADDITIONAL_TOKEN "_ISC_RET_NO_ADDITIONAL_TOKEN"
    unsigned long ISC_RET_REAUTHENTICATION "_ISC_RET_REAUTHENTICATION"
    unsigned long ISC_RET_CONFIDENTIALITY_ONLY "_ISC_RET_CONFIDENTIALITY_ONLY"

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw
    SECURITY_STATUS InitializeSecurityContextW(
        PCredHandle    phCredential,
        PCtxtHandle    phContext,
        LPWSTR         pTargetName,
        unsigned long  fContextReq,
        unsigned long  Reserved1,
        unsigned long  TargetDataRep,
        PSecBufferDesc pInput,
        unsigned long  Reserved2,
        PCtxtHandle    phNewContext,
        PSecBufferDesc pOutput,
        unsigned long  *pfContextAttr,
        PTimeStamp     ptsExpiry
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-deletesecuritycontext
    SECURITY_STATUS DeleteSecurityContext(
        PCtxtHandle phContext
    ) nogil

class TargetDataRep(enum.IntEnum):
    SECURITY_NATIVE_DREP = _SECURITY_NATIVE_DREP
    SECURITY_NETWORK_DREP = _SECURITY_NETWORK_DREP

cdef class SecurityContext:
    # cdef CtxtHandle handle
    # cdef TimeStamp raw_expiry
    # cdef int needs_free

    def __dealloc__(SecurityContext self):
        if self.needs_free:
            DeleteSecurityContext(&self.handle)
            self.needs_free = 0

    @property
    def expiry(SecurityContext self) -> int:
        return (<unsigned long long>self.raw_expiry.HighPart << 32) | self.raw_expiry.LowPart

def initialize_security_context(
    Credential credential,
    SecurityContext context,
    str target_name not None,
    unsigned long context_req,
    unsigned long target_data_rep,
    SecBufferDesc input_buffers not None,
    SecBufferDesc output_buffers not None,
) -> tuple[SecurityContext, int]:
    cdef PCredHandle cred_handle = NULL
    if credential:
        cred_handle = &credential.handle

    cdef PCtxtHandle in_context = NULL
    cdef SecurityContext out_context = None
    if context:
        in_context = &context.handle
        out_context = context
    else:
        in_context = NULL
        out_context = SecurityContext()

    cdef WideCharString target_name_wstr = WideCharString(target_name)
    cdef unsigned long context_attr = 0

    with nogil:
        res = InitializeSecurityContextW(
            cred_handle,
            in_context,
            target_name_wstr.buffer,
            context_req,
            0,
            target_data_rep,
            &input_buffers.raw,
            0,
            &out_context.handle,
            &output_buffers.raw,
            &context_attr,
            &out_context.raw_expiry,
        )

    if res != 0:
        PyErr_SetFromWindowsErr(res)

    out_context.needs_free = 1

    return out_context, context_attr
