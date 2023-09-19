# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from cpython.exc cimport PyErr_SetFromWindowsErr
from libc.stdlib cimport calloc, free, malloc

import dataclasses
import enum


cdef extern from "Security.h":
    unsigned long _SECBUFFER_VERSION "SECBUFFER_VERSION"

    unsigned long _SECBUFFER_EMPTY "SECBUFFER_EMPTY"
    unsigned long _SECBUFFER_DATA "SECBUFFER_DATA"
    unsigned long _SECBUFFER_TOKEN "SECBUFFER_TOKEN"
    unsigned long _SECBUFFER_PKG_PARAMS "SECBUFFER_PKG_PARAMS"
    unsigned long _SECBUFFER_MISSING "SECBUFFER_MISSING"
    unsigned long _SECBUFFER_EXTRA "SECBUFFER_EXTRA"
    unsigned long _SECBUFFER_STREAM_TRAILER "SECBUFFER_STREAM_TRAILER"
    unsigned long _SECBUFFER_STREAM_HEADER "SECBUFFER_STREAM_HEADER"
    unsigned long _SECBUFFER_NEGOTIATION_INFO "SECBUFFER_NEGOTIATION_INFO"
    unsigned long _SECBUFFER_PADDING "SECBUFFER_PADDING"
    unsigned long _SECBUFFER_STREAM "SECBUFFER_STREAM"
    unsigned long _SECBUFFER_MECHLIST "SECBUFFER_MECHLIST"
    unsigned long _SECBUFFER_MECHLIST_SIGNATURE "SECBUFFER_MECHLIST_SIGNATURE"
    unsigned long _SECBUFFER_TARGET "SECBUFFER_TARGET"
    unsigned long _SECBUFFER_CHANNEL_BINDINGS "SECBUFFER_CHANNEL_BINDINGS"
    unsigned long _SECBUFFER_CHANGE_PASS_RESPONSE "SECBUFFER_CHANGE_PASS_RESPONSE"
    unsigned long _SECBUFFER_TARGET_HOST "SECBUFFER_TARGET_HOST"
    unsigned long _SECBUFFER_ALERT "SECBUFFER_ALERT"
    unsigned long _SECBUFFER_APPLICATION_PROTOCOLS "SECBUFFER_APPLICATION_PROTOCOLS"
    unsigned long _SECBUFFER_SRTP_PROTECTION_PROFILES "SECBUFFER_SRTP_PROTECTION_PROFILES"
    unsigned long _SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER "SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER"
    unsigned long _SECBUFFER_TOKEN_BINDING "SECBUFFER_TOKEN_BINDING"
    unsigned long _SECBUFFER_PRESHARED_KEY "SECBUFFER_PRESHARED_KEY"
    unsigned long _SECBUFFER_PRESHARED_KEY_IDENTITY "SECBUFFER_PRESHARED_KEY_IDENTITY"
    unsigned long _SECBUFFER_DTLS_MTU "SECBUFFER_DTLS_MTU"
    unsigned long _SECBUFFER_SEND_GENERIC_TLS_EXTENSION "SECBUFFER_SEND_GENERIC_TLS_EXTENSION"
    unsigned long _SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION "SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION"
    unsigned long _SECBUFFER_FLAGS "SECBUFFER_FLAGS"
    unsigned long _SECBUFFER_TRAFFIC_SECRETS "SECBUFFER_TRAFFIC_SECRETS"
    unsigned long _SECBUFFER_CERTIFICATE_REQUEST_CONTEXT "SECBUFFER_CERTIFICATE_REQUEST_CONTEXT"

    unsigned long _SECBUFFER_ATTRMASK "SECBUFFER_ATTRMASK"
    unsigned long _SECBUFFER_READONLY "SECBUFFER_READONLY"
    unsigned long _SECBUFFER_READONLY_WITH_CHECKSUM "SECBUFFER_READONLY_WITH_CHECKSUM"
    unsigned long _SECBUFFER_RESERVED "SECBUFFER_RESERVED"

    cdef struct _SEC_CHANNEL_BINDINGS:
        unsigned long  dwInitiatorAddrType
        unsigned long  cbInitiatorLength
        unsigned long  dwInitiatorOffset
        unsigned long  dwAcceptorAddrType
        unsigned long  cbAcceptorLength
        unsigned long  dwAcceptorOffset
        unsigned long  cbApplicationDataLength
        unsigned long  dwApplicationDataOffset
    ctypedef _SEC_CHANNEL_BINDINGS SEC_CHANNEL_BINDINGS
    ctypedef SEC_CHANNEL_BINDINGS *PSEC_CHANNEL_BINDINGS

SECBUFFER_VERSION = _SECBUFFER_VERSION

class SecBufferFlags(enum.IntFlag):
    SECBUFFER_NONE = 0
    SECBUFFER_ATTRMASK = _SECBUFFER_ATTRMASK
    SECBUFFER_READONLY = _SECBUFFER_READONLY
    SECBUFFER_READONLY_WITH_CHECKSUM = _SECBUFFER_READONLY_WITH_CHECKSUM
    SECBUFFER_RESERVED = _SECBUFFER_RESERVED

class SecBufferType(enum.IntEnum):
    SECBUFFER_EMPTY = _SECBUFFER_EMPTY
    SECBUFFER_DATA = _SECBUFFER_DATA
    SECBUFFER_TOKEN = _SECBUFFER_TOKEN
    SECBUFFER_PKG_PARAMS = _SECBUFFER_PKG_PARAMS
    SECBUFFER_MISSING = _SECBUFFER_MISSING
    SECBUFFER_EXTRA = _SECBUFFER_EXTRA
    SECBUFFER_STREAM_TRAILER = _SECBUFFER_STREAM_TRAILER
    SECBUFFER_STREAM_HEADER = _SECBUFFER_STREAM_HEADER
    SECBUFFER_NEGOTIATION_INFO = _SECBUFFER_NEGOTIATION_INFO
    SECBUFFER_PADDING = _SECBUFFER_PADDING
    SECBUFFER_STREAM = _SECBUFFER_STREAM
    SECBUFFER_MECHLIST = _SECBUFFER_MECHLIST
    SECBUFFER_MECHLIST_SIGNATURE = _SECBUFFER_MECHLIST_SIGNATURE
    SECBUFFER_TARGET = _SECBUFFER_TARGET
    SECBUFFER_CHANNEL_BINDINGS = _SECBUFFER_CHANNEL_BINDINGS
    SECBUFFER_CHANGE_PASS_RESPONSE = _SECBUFFER_CHANGE_PASS_RESPONSE
    SECBUFFER_TARGET_HOST = _SECBUFFER_TARGET_HOST
    SECBUFFER_ALERT = _SECBUFFER_ALERT
    SECBUFFER_APPLICATION_PROTOCOLS = _SECBUFFER_APPLICATION_PROTOCOLS
    SECBUFFER_SRTP_PROTECTION_PROFILES = _SECBUFFER_SRTP_PROTECTION_PROFILES
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = _SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER
    SECBUFFER_TOKEN_BINDING = _SECBUFFER_TOKEN_BINDING
    SECBUFFER_PRESHARED_KEY = _SECBUFFER_PRESHARED_KEY
    SECBUFFER_PRESHARED_KEY_IDENTITY = _SECBUFFER_PRESHARED_KEY_IDENTITY
    SECBUFFER_DTLS_MTU = _SECBUFFER_DTLS_MTU
    SECBUFFER_SEND_GENERIC_TLS_EXTENSION = _SECBUFFER_SEND_GENERIC_TLS_EXTENSION
    SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION = _SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION
    SECBUFFER_FLAGS = _SECBUFFER_FLAGS
    SECBUFFER_TRAFFIC_SECRETS = _SECBUFFER_TRAFFIC_SECRETS
    SECBUFFER_CERTIFICATE_REQUEST_CONTEXT = _SECBUFFER_CERTIFICATE_REQUEST_CONTEXT


cdef class SecBufferDesc:
    # cdef _SecBufferDesc raw
    # cdef SecBuffer[:] _buffers

    def __cinit__(
        SecBufferDesc self,
        buffers: list[SecBuffer],
        *,
        unsigned long version = SECBUFFER_VERSION,
    ):
        self._buffers = buffers
        self.raw.ulVersion = version
        self.raw.cBuffers = len(buffers)
        if self.raw.cBuffers:
            self.raw.pBuffers = <PSecBuffer>calloc(sizeof(_SecBuffer), self.raw.cBuffers)
            if not self.raw.pBuffers:
                raise MemoryError("Cannot calloc SecBufferDesc buffers")

            for idx, buffer in enumerate(buffers):
                src = (<SecBuffer>buffer).raw

                self.raw.pBuffers[idx].cbBuffer = src.cbBuffer
                self.raw.pBuffers[idx].BufferType = src.BufferType
                self.raw.pBuffers[idx].pvBuffer = src.pvBuffer

    def __dealloc__(SecBufferDesc self):
        if self.raw.pBuffers:
            free(self.raw.pBuffers)
            self.raw.pBuffers = NULL
            self.raw.cBuffers = 0
        self._buffers = []

    def __iter__(SecBufferDesc self) -> list[SecBuffer]:
        return self._buffers.__iter__()

    def __len__(SecBufferDesc self) -> int:
        return self.raw.cBuffers

    def __getitem__(SecBufferDesc self, key: int) -> SecBuffer:
        return self._buffers[key]

    cdef void mark_as_allocated(SecBufferDesc self):
        for buffer in self._buffers:
            (<SecBuffer>buffer)._needs_free = 1

    cdef void sync_buffers(SecBufferDesc self):
        for idx in range(self.raw.cBuffers):
            (<SecBuffer>self._buffers[idx]).raw.cbBuffer = self.raw.pBuffers[idx].cbBuffer
            (<SecBuffer>self._buffers[idx]).raw.BufferType = self.raw.pBuffers[idx].BufferType
            (<SecBuffer>self._buffers[idx]).raw.pvBuffer = self.raw.pBuffers[idx].pvBuffer

    @property
    def version(SecBuffer self) -> int:
        return self.raw.ulVersion

cdef class SecBuffer:
    # cdef _SecBuffer raw
    # cdef unsigned char[:] _buffer
    # cdef int _needs_free

    def __cinit__(
        SecBuffer self,
        unsigned char[:] data,
        buffer_type: SecBufferType | int,
        buffer_flags: SecBufferFlags | int = 0,
    ):
        self.raw.BufferType = int(buffer_type) | int(buffer_flags)

        if data is not None and len(data):
            self._buffer = data
            self.raw.cbBuffer = <unsigned long>len(data)
            self.raw.pvBuffer = &self._buffer[0]
        else:
            self._buffer = None
            self.raw.cbBuffer = 0
            self.raw.pvBuffer = NULL

    def __dealloc__(SecBuffer self):
        if self.raw.pvBuffer and self._needs_free:
            FreeContextBuffer(self.raw.pvBuffer)
            self._needs_free = 0

        self.raw.pvBuffer = NULL
        self.raw.cbBuffer = 0
        self.raw.BufferType = _SECBUFFER_EMPTY

    def __repr__(SecBuffer self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'data': f"bytearray({self.data!r})",
            'buffer_type': self.buffer_type,
            'buffer_flags': self.buffer_flags,
        }.items()]

        return f"SecBuffer({', '.join(kwargs)})"

    def __str__(SecBuffer self) -> str:
        val = self.buffer_type.name
        buffer_flags = self.buffer_flags
        if buffer_flags:
            val = f"{val}|{buffer_flags.name}"

        return val

    @property
    def count(SecBuffer self) -> int:
        return self.raw.cbBuffer

    @property
    def data(SecBuffer self) -> bytes:
        return bytes(self.dangerous_get_view())

    @property
    def buffer_type(SecBuffer self) -> SecBufferType:
        return SecBufferType(self.raw.BufferType & ~_SECBUFFER_ATTRMASK)

    @property
    def buffer_flags(SecBuffer self) -> SecBufferFlags:
        return SecBufferFlags(self.raw.BufferType & _SECBUFFER_ATTRMASK)

    def dangerous_get_view(SecBuffer self) -> memoryview:
        if self.raw.pvBuffer == NULL or self.raw.cbBuffer == 0:
            return memoryview(b"")
        else:
            return memoryview(<char[:self.raw.cbBuffer]>self.raw.pvBuffer)


cdef class SecChannelBindings:
    cdef PSEC_CHANNEL_BINDINGS raw

    def __init__(
        SecChannelBindings self,
        *,
        unsigned long initiator_addr_type = 0,
        const unsigned char[:] initiator_addr = None,
        unsigned long acceptor_addr_type = 0,
        const unsigned char[:] acceptor_addr = None,
        const unsigned char[:] application_data = None,
    ):
        offset = sizeof(SEC_CHANNEL_BINDINGS)

        initiator_offset = 0
        initiator_len = 0
        if initiator_addr is not None:
            initiator_offset = offset
            initiator_len = len(initiator_addr)
            offset += initiator_len

        acceptor_offset = 0
        acceptor_len = 0
        if acceptor_addr is not None:
            acceptor_offset = offset
            acceptor_len = len(acceptor_addr)
            offset += acceptor_len

        application_offset = 0
        application_len = 0
        if application_data is not None:
            application_offset = offset
            application_len = len(application_data)

        raw_length = sizeof(SEC_CHANNEL_BINDINGS) + initiator_len + acceptor_len + application_len
        self.raw = <PSEC_CHANNEL_BINDINGS>malloc(raw_length)
        if not self.raw:
            raise MemoryError("Cannot malloc SecChannelBindings buffers")

        cdef unsigned char[:] raw_ptr = <unsigned char[:raw_length]><unsigned char*>self.raw

        self.raw.dwInitiatorAddrType = initiator_addr_type
        self.raw.cbInitiatorLength = initiator_len
        self.raw.dwInitiatorOffset = initiator_offset
        if initiator_offset:
            raw_ptr[initiator_offset : initiator_offset + initiator_len] = initiator_addr.copy()

        self.raw.dwAcceptorAddrType = acceptor_addr_type
        self.raw.cbAcceptorLength = acceptor_len
        self.raw.dwAcceptorOffset = acceptor_offset
        if acceptor_offset:
            raw_ptr[acceptor_offset : acceptor_offset + acceptor_len] = acceptor_addr.copy()

        self.raw.cbApplicationDataLength = application_len
        self.raw.dwApplicationDataOffset = application_offset
        if application_offset:
            raw_ptr[application_offset : application_offset + application_len] = application_data.copy()

    def __dealloc__(SecChannelBindings self):
        if self.raw:
            free(self.raw)
            self.raw = NULL

    cdef char[:] get_raw_view(SecChannelBindings self):
        data_len = sizeof(SEC_CHANNEL_BINDINGS) + \
            self.raw.cbInitiatorLength + \
            self.raw.cbAcceptorLength + \
            self.raw.cbApplicationDataLength
        return <char[:data_len]><char*>self.raw

    def __repr__(SecChannelBindings self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'initiator_addr_type': self.initiator_addr_type,
            'initiator_addr': repr(self.initiator_addr),
            'acceptor_addr_type': self.acceptor_addr_type,
            'acceptor_addr': repr(self.acceptor_addr),
            'application_data': repr(self.application_data),
        }.items()]

        return f"SecChannelBindings({', '.join(kwargs)})"

    @property
    def initiator_addr_type(SecChannelBindings self) -> int:
        return self.raw.dwInitiatorAddrType

    @property
    def initiator_addr(SecChannelBindings self) -> bytes | None:
        val_len = self.raw.cbInitiatorLength
        val_offset = self.raw.dwInitiatorOffset

        if val_offset:
            return (<char *>self.raw)[val_offset : val_offset + val_len]

        else:
            return None

    @property
    def acceptor_addr_type(SecChannelBindings self) -> int | None:
        return self.raw.dwAcceptorAddrType

    @property
    def acceptor_addr(SecChannelBindings self) -> bytes:
        val_len = self.raw.cbAcceptorLength
        val_offset = self.raw.dwAcceptorOffset

        if val_offset:
            return (<char *>self.raw)[val_offset : val_offset + val_len]

        else:
            return None

    @property
    def application_data(SecChannelBindings self) -> bytes | None:
        val_len = self.raw.cbApplicationDataLength
        val_offset = self.raw.dwApplicationDataOffset

        if val_offset:
            return (<char *>self.raw)[val_offset : val_offset + val_len]

        else:
            return None

    def get_sec_buffer_copy(SecChannelBindings self) -> SecBuffer:
        data = bytearray(self.get_raw_view())
        return SecBuffer(data, _SECBUFFER_CHANNEL_BINDINGS)

    def dangerous_get_sec_buffer(SecChannelBindings self) -> SecBuffer:
        data_len = sizeof(SEC_CHANNEL_BINDINGS) + \
            self.raw.cbInitiatorLength + \
            self.raw.cbAcceptorLength + \
            self.raw.cbApplicationDataLength
        view = memoryview(<char[:data_len]><char*>self.raw)

        return SecBuffer(view, _SECBUFFER_CHANNEL_BINDINGS)
