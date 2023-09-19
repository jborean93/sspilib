# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import collections
import enum

from cpython.exc cimport PyErr_SetFromWindowsErr

from sspi._credential cimport Credential
from sspi._security_buffer cimport PSecBufferDesc, SecBufferDesc
from sspi._text cimport WideCharString
from sspi._win32_types cimport *

from sspi._ntstatus import NtStatus


cdef extern from "Security.h":
    unsigned long _SECURITY_NATIVE_DREP "SECURITY_NATIVE_DREP"
    unsigned long _SECURITY_NETWORK_DREP "SECURITY_NETWORK_DREP"

    unsigned long _ASC_REQ_DELEGATE "ASC_REQ_DELEGATE"
    unsigned long _ASC_REQ_MUTUAL_AUTH "ASC_REQ_MUTUAL_AUTH"
    unsigned long _ASC_REQ_REPLAY_DETECT "ASC_REQ_REPLAY_DETECT"
    unsigned long _ASC_REQ_SEQUENCE_DETECT "ASC_REQ_SEQUENCE_DETECT"
    unsigned long _ASC_REQ_CONFIDENTIALITY "ASC_REQ_CONFIDENTIALITY"
    unsigned long _ASC_REQ_USE_SESSION_KEY "ASC_REQ_USE_SESSION_KEY"
    unsigned long _ASC_REQ_SESSION_TICKET "ASC_REQ_SESSION_TICKET"
    unsigned long _ASC_REQ_ALLOCATE_MEMORY "ASC_REQ_ALLOCATE_MEMORY"
    unsigned long _ASC_REQ_USE_DCE_STYLE "ASC_REQ_USE_DCE_STYLE"
    unsigned long _ASC_REQ_DATAGRAM "ASC_REQ_DATAGRAM"
    unsigned long _ASC_REQ_CONNECTION "ASC_REQ_CONNECTION"
    unsigned long _ASC_REQ_CALL_LEVEL "ASC_REQ_CALL_LEVEL"
    unsigned long _ASC_REQ_FRAGMENT_SUPPLIED "ASC_REQ_FRAGMENT_SUPPLIED"
    unsigned long _ASC_REQ_EXTENDED_ERROR "ASC_REQ_EXTENDED_ERROR"
    unsigned long _ASC_REQ_STREAM "ASC_REQ_STREAM"
    unsigned long _ASC_REQ_INTEGRITY "ASC_REQ_INTEGRITY"
    unsigned long _ASC_REQ_LICENSING "ASC_REQ_LICENSING"
    unsigned long _ASC_REQ_IDENTIFY "ASC_REQ_IDENTIFY"
    unsigned long _ASC_REQ_ALLOW_NULL_SESSION "ASC_REQ_ALLOW_NULL_SESSION"
    unsigned long _ASC_REQ_ALLOW_NON_USER_LOGONS "ASC_REQ_ALLOW_NON_USER_LOGONS"
    unsigned long _ASC_REQ_ALLOW_CONTEXT_REPLAY "ASC_REQ_ALLOW_CONTEXT_REPLAY"
    unsigned long _ASC_REQ_FRAGMENT_TO_FIT "ASC_REQ_FRAGMENT_TO_FIT"
    unsigned long _ASC_REQ_NO_TOKEN "ASC_REQ_NO_TOKEN"
    unsigned long _ASC_REQ_PROXY_BINDINGS "ASC_REQ_PROXY_BINDINGS"
    unsigned long _ASC_REQ_ALLOW_MISSING_BINDINGS "ASC_REQ_ALLOW_MISSING_BINDINGS"

    unsigned long _ASC_RET_DELEGATE "ASC_RET_DELEGATE"
    unsigned long _ASC_RET_MUTUAL_AUTH "ASC_RET_MUTUAL_AUTH"
    unsigned long _ASC_RET_REPLAY_DETECT "ASC_RET_REPLAY_DETECT"
    unsigned long _ASC_RET_SEQUENCE_DETECT "ASC_RET_SEQUENCE_DETECT"
    unsigned long _ASC_RET_CONFIDENTIALITY "ASC_RET_CONFIDENTIALITY"
    unsigned long _ASC_RET_USE_SESSION_KEY "ASC_RET_USE_SESSION_KEY"
    unsigned long _ASC_RET_SESSION_TICKET "ASC_RET_SESSION_TICKET"
    unsigned long _ASC_RET_ALLOCATED_MEMORY "ASC_RET_ALLOCATED_MEMORY"
    unsigned long _ASC_RET_USED_DCE_STYLE "ASC_RET_USED_DCE_STYLE"
    unsigned long _ASC_RET_DATAGRAM "ASC_RET_DATAGRAM"
    unsigned long _ASC_RET_CONNECTION "ASC_RET_CONNECTION"
    unsigned long _ASC_RET_CALL_LEVEL "ASC_RET_CALL_LEVEL"
    unsigned long _ASC_RET_THIRD_LEG_FAILED "ASC_RET_THIRD_LEG_FAILED"
    unsigned long _ASC_RET_EXTENDED_ERROR "ASC_RET_EXTENDED_ERROR"
    unsigned long _ASC_RET_STREAM "ASC_RET_STREAM"
    unsigned long _ASC_RET_INTEGRITY "ASC_RET_INTEGRITY"
    unsigned long _ASC_RET_LICENSING "ASC_RET_LICENSING"
    unsigned long _ASC_RET_IDENTIFY "ASC_RET_IDENTIFY"
    unsigned long _ASC_RET_NULL_SESSION "ASC_RET_NULL_SESSION"
    unsigned long _ASC_RET_ALLOW_NON_USER_LOGONS "ASC_RET_ALLOW_NON_USER_LOGONS"
    unsigned long _ASC_RET_ALLOW_CONTEXT_REPLAY "ASC_RET_ALLOW_CONTEXT_REPLAY"
    unsigned long _ASC_RET_FRAGMENT_ONLY "ASC_RET_FRAGMENT_ONLY"
    unsigned long _ASC_RET_NO_TOKEN "ASC_RET_NO_TOKEN"
    unsigned long _ASC_RET_NO_ADDITIONAL_TOKEN "ASC_RET_NO_ADDITIONAL_TOKEN"

    unsigned long _ISC_REQ_DELEGATE "ISC_REQ_DELEGATE"
    unsigned long _ISC_REQ_MUTUAL_AUTH "ISC_REQ_MUTUAL_AUTH"
    unsigned long _ISC_REQ_REPLAY_DETECT "ISC_REQ_REPLAY_DETECT"
    unsigned long _ISC_REQ_SEQUENCE_DETECT "ISC_REQ_SEQUENCE_DETECT"
    unsigned long _ISC_REQ_CONFIDENTIALITY "ISC_REQ_CONFIDENTIALITY"
    unsigned long _ISC_REQ_USE_SESSION_KEY "ISC_REQ_USE_SESSION_KEY"
    unsigned long _ISC_REQ_PROMPT_FOR_CREDS "ISC_REQ_PROMPT_FOR_CREDS"
    unsigned long _ISC_REQ_USE_SUPPLIED_CREDS "ISC_REQ_USE_SUPPLIED_CREDS"
    unsigned long _ISC_REQ_ALLOCATE_MEMORY "ISC_REQ_ALLOCATE_MEMORY"
    unsigned long _ISC_REQ_USE_DCE_STYLE "ISC_REQ_USE_DCE_STYLE"
    unsigned long _ISC_REQ_DATAGRAM "ISC_REQ_DATAGRAM"
    unsigned long _ISC_REQ_CONNECTION "ISC_REQ_CONNECTION"
    unsigned long _ISC_REQ_CALL_LEVEL "ISC_REQ_CALL_LEVEL"
    unsigned long _ISC_REQ_FRAGMENT_SUPPLIED "ISC_REQ_FRAGMENT_SUPPLIED"
    unsigned long _ISC_REQ_EXTENDED_ERROR "ISC_REQ_EXTENDED_ERROR"
    unsigned long _ISC_REQ_STREAM "ISC_REQ_STREAM"
    unsigned long _ISC_REQ_INTEGRITY "ISC_REQ_INTEGRITY"
    unsigned long _ISC_REQ_IDENTIFY "ISC_REQ_IDENTIFY"
    unsigned long _ISC_REQ_NULL_SESSION "ISC_REQ_NULL_SESSION"
    unsigned long _ISC_REQ_MANUAL_CRED_VALIDATION "ISC_REQ_MANUAL_CRED_VALIDATION"
    unsigned long _ISC_REQ_RESERVED1 "ISC_REQ_RESERVED1"
    unsigned long _ISC_REQ_FRAGMENT_TO_FIT "ISC_REQ_FRAGMENT_TO_FIT"
    unsigned long _ISC_REQ_FORWARD_CREDENTIALS "ISC_REQ_FORWARD_CREDENTIALS"
    unsigned long _ISC_REQ_NO_INTEGRITY "ISC_REQ_NO_INTEGRITY"
    unsigned long _ISC_REQ_USE_HTTP_STYLE "ISC_REQ_USE_HTTP_STYLE"
    unsigned long _ISC_REQ_UNVERIFIED_TARGET_NAME "ISC_REQ_UNVERIFIED_TARGET_NAME"
    unsigned long _ISC_REQ_CONFIDENTIALITY_ONLY "ISC_REQ_CONFIDENTIALITY_ONLY"

    unsigned long _ISC_RET_DELEGATE "ISC_RET_DELEGATE"
    unsigned long _ISC_RET_MUTUAL_AUTH "ISC_RET_MUTUAL_AUTH"
    unsigned long _ISC_RET_REPLAY_DETECT "ISC_RET_REPLAY_DETECT"
    unsigned long _ISC_RET_SEQUENCE_DETECT "ISC_RET_SEQUENCE_DETECT"
    unsigned long _ISC_RET_CONFIDENTIALITY "ISC_RET_CONFIDENTIALITY"
    unsigned long _ISC_RET_USE_SESSION_KEY "ISC_RET_USE_SESSION_KEY"
    unsigned long _ISC_RET_USED_COLLECTED_CREDS "ISC_RET_USED_COLLECTED_CREDS"
    unsigned long _ISC_RET_USED_SUPPLIED_CREDS "ISC_RET_USED_SUPPLIED_CREDS"
    unsigned long _ISC_RET_ALLOCATED_MEMORY "ISC_RET_ALLOCATED_MEMORY"
    unsigned long _ISC_RET_USED_DCE_STYLE "ISC_RET_USED_DCE_STYLE"
    unsigned long _ISC_RET_DATAGRAM "ISC_RET_DATAGRAM"
    unsigned long _ISC_RET_CONNECTION "ISC_RET_CONNECTION"
    unsigned long _ISC_RET_INTERMEDIATE_RETURN "ISC_RET_INTERMEDIATE_RETURN"
    unsigned long _ISC_RET_CALL_LEVEL "ISC_RET_CALL_LEVEL"
    unsigned long _ISC_RET_EXTENDED_ERROR "ISC_RET_EXTENDED_ERROR"
    unsigned long _ISC_RET_STREAM "ISC_RET_STREAM"
    unsigned long _ISC_RET_INTEGRITY "ISC_RET_INTEGRITY"
    unsigned long _ISC_RET_IDENTIFY "ISC_RET_IDENTIFY"
    unsigned long _ISC_RET_NULL_SESSION "ISC_RET_NULL_SESSION"
    unsigned long _ISC_RET_MANUAL_CRED_VALIDATION "ISC_RET_MANUAL_CRED_VALIDATION"
    unsigned long _ISC_RET_RESERVED1 "ISC_RET_RESERVED1"
    unsigned long _ISC_RET_FRAGMENT_ONLY "ISC_RET_FRAGMENT_ONLY"
    unsigned long _ISC_RET_FORWARD_CREDENTIALS "ISC_RET_FORWARD_CREDENTIALS"
    unsigned long _ISC_RET_USED_HTTP_STYLE "ISC_RET_USED_HTTP_STYLE"
    unsigned long _ISC_RET_NO_ADDITIONAL_TOKEN "ISC_RET_NO_ADDITIONAL_TOKEN"
    unsigned long _ISC_RET_REAUTHENTICATION "ISC_RET_REAUTHENTICATION"
    unsigned long _ISC_RET_CONFIDENTIALITY_ONLY "ISC_RET_CONFIDENTIALITY_ONLY"

    # https://learn.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--general
    SECURITY_STATUS AcceptSecurityContext(
        PCredHandle    phCredential,
        PCtxtHandle    phContext,
        PSecBufferDesc pInput,
        unsigned long  fContextReq,
        unsigned long  TargetDataRep,
        PCtxtHandle    phNewContext,
        PSecBufferDesc pOutput,
        unsigned long  *pfContextAttr,
        PTimeStamp     ptsExpiry
    ) nogil

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-completeauthtoken
    SECURITY_STATUS CompleteAuthToken(
        PCtxtHandle    phContext,
        PSecBufferDesc pToken
    ) nogil

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

class AscReq(enum.IntFlag):
    ASC_REQ_DELEGATE = _ASC_REQ_DELEGATE
    ASC_REQ_MUTUAL_AUTH = _ASC_REQ_MUTUAL_AUTH
    ASC_REQ_REPLAY_DETECT = _ASC_REQ_REPLAY_DETECT
    ASC_REQ_SEQUENCE_DETECT = _ASC_REQ_SEQUENCE_DETECT
    ASC_REQ_CONFIDENTIALITY = _ASC_REQ_CONFIDENTIALITY
    ASC_REQ_USE_SESSION_KEY = _ASC_REQ_USE_SESSION_KEY
    ASC_REQ_SESSION_TICKET = _ASC_REQ_SESSION_TICKET
    ASC_REQ_ALLOCATE_MEMORY = _ASC_REQ_ALLOCATE_MEMORY
    ASC_REQ_USE_DCE_STYLE = _ASC_REQ_USE_DCE_STYLE
    ASC_REQ_DATAGRAM = _ASC_REQ_DATAGRAM
    ASC_REQ_CONNECTION = _ASC_REQ_CONNECTION
    ASC_REQ_CALL_LEVEL = _ASC_REQ_CALL_LEVEL
    ASC_REQ_FRAGMENT_SUPPLIED = _ASC_REQ_FRAGMENT_SUPPLIED
    ASC_REQ_EXTENDED_ERROR = _ASC_REQ_EXTENDED_ERROR
    ASC_REQ_STREAM = _ASC_REQ_STREAM
    ASC_REQ_INTEGRITY = _ASC_REQ_INTEGRITY
    ASC_REQ_LICENSING = _ASC_REQ_LICENSING
    ASC_REQ_IDENTIFY = _ASC_REQ_IDENTIFY
    ASC_REQ_ALLOW_NULL_SESSION = _ASC_REQ_ALLOW_NULL_SESSION
    ASC_REQ_ALLOW_NON_USER_LOGONS = _ASC_REQ_ALLOW_NON_USER_LOGONS
    ASC_REQ_ALLOW_CONTEXT_REPLAY = _ASC_REQ_ALLOW_CONTEXT_REPLAY
    ASC_REQ_FRAGMENT_TO_FIT = _ASC_REQ_FRAGMENT_TO_FIT
    ASC_REQ_NO_TOKEN = _ASC_REQ_NO_TOKEN
    ASC_REQ_PROXY_BINDINGS = _ASC_REQ_PROXY_BINDINGS
    ASC_REQ_ALLOW_MISSING_BINDINGS = _ASC_REQ_ALLOW_MISSING_BINDINGS

class AscRet(enum.IntFlag):
    ASC_RET_DELEGATE = _ASC_RET_DELEGATE
    ASC_RET_MUTUAL_AUTH = _ASC_RET_MUTUAL_AUTH
    ASC_RET_REPLAY_DETECT = _ASC_RET_REPLAY_DETECT
    ASC_RET_SEQUENCE_DETECT = _ASC_RET_SEQUENCE_DETECT
    ASC_RET_CONFIDENTIALITY = _ASC_RET_CONFIDENTIALITY
    ASC_RET_USE_SESSION_KEY = _ASC_RET_USE_SESSION_KEY
    ASC_RET_SESSION_TICKET = _ASC_RET_SESSION_TICKET
    ASC_RET_ALLOCATED_MEMORY = _ASC_RET_ALLOCATED_MEMORY
    ASC_RET_USED_DCE_STYLE = _ASC_RET_USED_DCE_STYLE
    ASC_RET_DATAGRAM = _ASC_RET_DATAGRAM
    ASC_RET_CONNECTION = _ASC_RET_CONNECTION
    ASC_RET_CALL_LEVEL = _ASC_RET_CALL_LEVEL
    ASC_RET_THIRD_LEG_FAILED = _ASC_RET_THIRD_LEG_FAILED
    ASC_RET_EXTENDED_ERROR = _ASC_RET_EXTENDED_ERROR
    ASC_RET_STREAM = _ASC_RET_STREAM
    ASC_RET_INTEGRITY = _ASC_RET_INTEGRITY
    ASC_RET_LICENSING = _ASC_RET_LICENSING
    ASC_RET_IDENTIFY = _ASC_RET_IDENTIFY
    ASC_RET_NULL_SESSION = _ASC_RET_NULL_SESSION
    ASC_RET_ALLOW_NON_USER_LOGONS = _ASC_RET_ALLOW_NON_USER_LOGONS
    ASC_RET_ALLOW_CONTEXT_REPLAY = _ASC_RET_ALLOW_CONTEXT_REPLAY
    ASC_RET_FRAGMENT_ONLY = _ASC_RET_FRAGMENT_ONLY
    ASC_RET_NO_TOKEN = _ASC_RET_NO_TOKEN
    ASC_RET_NO_ADDITIONAL_TOKEN = _ASC_RET_NO_ADDITIONAL_TOKEN

class IscReq(enum.IntFlag):
    ISC_REQ_DELEGATE = _ISC_REQ_DELEGATE
    ISC_REQ_MUTUAL_AUTH = _ISC_REQ_MUTUAL_AUTH
    ISC_REQ_REPLAY_DETECT = _ISC_REQ_REPLAY_DETECT
    ISC_REQ_SEQUENCE_DETECT = _ISC_REQ_SEQUENCE_DETECT
    ISC_REQ_CONFIDENTIALITY = _ISC_REQ_CONFIDENTIALITY
    ISC_REQ_USE_SESSION_KEY = _ISC_REQ_USE_SESSION_KEY
    ISC_REQ_PROMPT_FOR_CREDS = _ISC_REQ_PROMPT_FOR_CREDS
    ISC_REQ_USE_SUPPLIED_CREDS = _ISC_REQ_USE_SUPPLIED_CREDS
    ISC_REQ_ALLOCATE_MEMORY = _ISC_REQ_ALLOCATE_MEMORY
    ISC_REQ_USE_DCE_STYLE = _ISC_REQ_USE_DCE_STYLE
    ISC_REQ_DATAGRAM = _ISC_REQ_DATAGRAM
    ISC_REQ_CONNECTION = _ISC_REQ_CONNECTION
    ISC_REQ_CALL_LEVEL = _ISC_REQ_CALL_LEVEL
    ISC_REQ_FRAGMENT_SUPPLIED = _ISC_REQ_FRAGMENT_SUPPLIED
    ISC_REQ_EXTENDED_ERROR = _ISC_REQ_EXTENDED_ERROR
    ISC_REQ_STREAM = _ISC_REQ_STREAM
    ISC_REQ_INTEGRITY = _ISC_REQ_INTEGRITY
    ISC_REQ_IDENTIFY = _ISC_REQ_IDENTIFY
    ISC_REQ_NULL_SESSION = _ISC_REQ_NULL_SESSION
    ISC_REQ_MANUAL_CRED_VALIDATION = _ISC_REQ_MANUAL_CRED_VALIDATION
    ISC_REQ_RESERVED1 = _ISC_REQ_RESERVED1
    ISC_REQ_FRAGMENT_TO_FIT = _ISC_REQ_FRAGMENT_TO_FIT
    ISC_REQ_FORWARD_CREDENTIALS = _ISC_REQ_FORWARD_CREDENTIALS
    ISC_REQ_NO_INTEGRITY = _ISC_REQ_NO_INTEGRITY
    ISC_REQ_USE_HTTP_STYLE = _ISC_REQ_USE_HTTP_STYLE
    ISC_REQ_UNVERIFIED_TARGET_NAME = _ISC_REQ_UNVERIFIED_TARGET_NAME
    ISC_REQ_CONFIDENTIALITY_ONLY = _ISC_REQ_CONFIDENTIALITY_ONLY

class IscRet(enum.IntFlag):
    ISC_RET_DELEGATE = _ISC_RET_DELEGATE
    ISC_RET_MUTUAL_AUTH = _ISC_RET_MUTUAL_AUTH
    ISC_RET_REPLAY_DETECT = _ISC_RET_REPLAY_DETECT
    ISC_RET_SEQUENCE_DETECT = _ISC_RET_SEQUENCE_DETECT
    ISC_RET_CONFIDENTIALITY = _ISC_RET_CONFIDENTIALITY
    ISC_RET_USE_SESSION_KEY = _ISC_RET_USE_SESSION_KEY
    ISC_RET_USED_COLLECTED_CREDS = _ISC_RET_USED_COLLECTED_CREDS
    ISC_RET_USED_SUPPLIED_CREDS = _ISC_RET_USED_SUPPLIED_CREDS
    ISC_RET_ALLOCATED_MEMORY = _ISC_RET_ALLOCATED_MEMORY
    ISC_RET_USED_DCE_STYLE = _ISC_RET_USED_DCE_STYLE
    ISC_RET_DATAGRAM = _ISC_RET_DATAGRAM
    ISC_RET_CONNECTION = _ISC_RET_CONNECTION
    ISC_RET_INTERMEDIATE_RETURN = _ISC_RET_INTERMEDIATE_RETURN
    ISC_RET_CALL_LEVEL = _ISC_RET_CALL_LEVEL
    ISC_RET_EXTENDED_ERROR = _ISC_RET_EXTENDED_ERROR
    ISC_RET_STREAM = _ISC_RET_STREAM
    ISC_RET_INTEGRITY = _ISC_RET_INTEGRITY
    ISC_RET_IDENTIFY = _ISC_RET_IDENTIFY
    ISC_RET_NULL_SESSION = _ISC_RET_NULL_SESSION
    ISC_RET_MANUAL_CRED_VALIDATION = _ISC_RET_MANUAL_CRED_VALIDATION
    ISC_RET_RESERVED1 = _ISC_RET_RESERVED1
    ISC_RET_FRAGMENT_ONLY = _ISC_RET_FRAGMENT_ONLY
    ISC_RET_FORWARD_CREDENTIALS = _ISC_RET_FORWARD_CREDENTIALS
    ISC_RET_USED_HTTP_STYLE = _ISC_RET_USED_HTTP_STYLE
    ISC_RET_NO_ADDITIONAL_TOKEN = _ISC_RET_NO_ADDITIONAL_TOKEN
    ISC_RET_REAUTHENTICATION = _ISC_RET_REAUTHENTICATION
    ISC_RET_CONFIDENTIALITY_ONLY = _ISC_RET_CONFIDENTIALITY_ONLY

cdef class SecurityContext:
    # cdef CtxtHandle raw
    # cdef TimeStamp raw_expiry
    # cdef int _needs_free

    def __dealloc__(SecurityContext self):
        if self._needs_free:
            DeleteSecurityContext(&self.raw)
            self._needs_free = 0

    @property
    def expiry(SecurityContext self) -> int:
        return (<unsigned long long>self.raw_expiry.HighPart << 32) | self.raw_expiry.LowPart

cdef class AcceptorSecurityContext(SecurityContext):
    cdef unsigned long raw_context_attr

    @property
    def context_attr(AcceptorSecurityContext self) -> AscRet:
        return AscRet(self.raw_context_attr)

cdef class InitiatorSecurityContext(SecurityContext):
    cdef unsigned long raw_context_attr

    @property
    def context_attr(InitiatorSecurityContext self) -> IscRet:
        return IscRet(self.raw_context_attr)

AcceptContextResult = collections.namedtuple(
    'AcceptContextResult',
    ['context', 'result'],
)

InitializeContextResult = collections.namedtuple(
    'InitializeContextResult',
    ['context', 'result'],
)

def accept_security_context(
    Credential credential,
    AcceptorSecurityContext context,
    SecBufferDesc input_buffers,
    unsigned long context_req,
    unsigned long target_data_rep,
    SecBufferDesc output_buffers,
) -> AcceptContextResult:
    cdef PCredHandle cred_handle = NULL
    if credential:
        cred_handle = &credential.raw

    cdef PCtxtHandle in_context = NULL
    cdef AcceptorSecurityContext out_context = None
    if context:
        in_context = &context.raw
        out_context = context
    else:
        in_context = NULL
        out_context = AcceptorSecurityContext()

    cdef PSecBufferDesc input_buffers_raw = NULL
    if input_buffers:
        input_buffers_raw = &input_buffers.raw
    cdef PSecBufferDesc output_buffers_raw = NULL
    if output_buffers:
        output_buffers_raw = &output_buffers.raw

    with nogil:
        res = AcceptSecurityContext(
            cred_handle,
            in_context,
            input_buffers_raw,
            context_req,
            target_data_rep,
            &out_context.raw,
            output_buffers_raw,
            &out_context.raw_context_attr,
            &out_context.raw_expiry,
        )

    if res not in [
        NtStatus.SEC_I_COMPLETE_AND_CONTINUE,
        NtStatus.SEC_I_COMPLETE_NEEDED,
        NtStatus.SEC_I_CONTINUE_NEEDED,
        NtStatus.SEC_E_OK,
    ]:
        PyErr_SetFromWindowsErr(res)

    if output_buffers:
        output_buffers.sync_buffers()
        if context_req & _ASC_REQ_ALLOCATE_MEMORY:
            output_buffers.mark_as_allocated()
    out_context._needs_free = 1

    return AcceptContextResult(
        context=out_context,
        result=NtStatus(res),
    )

def complete_auth_token(
    SecurityContext context not None,
    SecBufferDesc token not None,
) -> None:
    with nogil:
        res = CompleteAuthToken(
            &context.raw,
            &token.raw,
        )

    if res:
        PyErr_SetFromWindowsErr(res)

def initialize_security_context(
    Credential credential,
    InitiatorSecurityContext context,
    str target_name not None,
    unsigned long context_req,
    unsigned long target_data_rep,
    SecBufferDesc input_buffers,
    SecBufferDesc output_buffers,
) -> InitializeContextResult:
    cdef PCredHandle cred_handle = NULL
    if credential:
        cred_handle = &credential.raw

    cdef PCtxtHandle in_context = NULL
    cdef InitiatorSecurityContext out_context = None
    if context:
        in_context = &context.raw
        out_context = context
    else:
        in_context = NULL
        out_context = InitiatorSecurityContext()

    cdef WideCharString target_name_wchar = WideCharString(target_name)

    cdef PSecBufferDesc input_buffers_raw = NULL
    if input_buffers:
        input_buffers_raw = &input_buffers.raw
    cdef PSecBufferDesc output_buffers_raw = NULL
    if output_buffers:
        output_buffers_raw = &output_buffers.raw

    with nogil:
        res = InitializeSecurityContextW(
            cred_handle,
            in_context,
            target_name_wchar.raw,
            context_req,
            0,
            target_data_rep,
            input_buffers_raw,
            0,
            &out_context.raw,
            output_buffers_raw,
            &out_context.raw_context_attr,
            &out_context.raw_expiry,
        )

    if res not in [
        NtStatus.SEC_I_COMPLETE_AND_CONTINUE,
        NtStatus.SEC_I_COMPLETE_NEEDED,
        NtStatus.SEC_I_CONTINUE_NEEDED,
        NtStatus.SEC_E_OK,
    ]:
        PyErr_SetFromWindowsErr(res)

    if output_buffers:
        output_buffers.sync_buffers()
        if context_req & _ISC_REQ_ALLOCATE_MEMORY:
            output_buffers.mark_as_allocated()
    out_context._needs_free = 1

    return InitializeContextResult(
        context=out_context,
        result=NtStatus(res),
    )
