# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from cpython.exc cimport PyErr_SetFromWindowsErr
from libc.stdlib cimport calloc, free

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
                dst = self.raw.pBuffers[idx]

                dst.cbBuffer = src.cbBuffer
                dst.BufferType = src.BufferType
                dst.pvBuffer = src.pvBuffer

    def __iter__(SecBufferDesc self) -> list[SecBuffer]:
        return self._buffers.__iter__()

    def __len__(SecBufferDesc self) -> int:
        return self.raw.cBuffers

    def __getitem__(SecBufferDesc self, key: int) -> SecBuffer:
        return self._buffers[key]

    cdef void sync_buffers(SecBufferDesc self):
        for idx in range(self.raw.cBuffers):
            src = self.raw.pBuffers[idx]
            dst = (<SecBuffer>self._buffers[idx]).raw

            dst.cbBuffer = src.cbBuffer
            dst.BufferType = src.BufferType
            dst.pvBuffer = src.pvBuffer

    @property
    def version(SecBuffer self) -> int:
        return self.raw.ulVersion

cdef class SecBuffer:
    cdef _SecBuffer raw
    cdef unsigned char[:] _buffer

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

    def __repr__(SecBuffer self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'data': self.data,
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
    def data(SecBuffer self) -> bytes | None:
        if self.raw.pvBuffer == NULL or self.raw.cbBuffer == 0:
            return None
        else:
            return (<char *>self.raw.pvBuffer)[:self.raw.cbBuffer]

    @property
    def buffer_type(SecBuffer self) -> SecBufferType:
        return SecBufferType(self.raw.BufferType & ~_SECBUFFER_ATTRMASK)

    @property
    def buffer_flags(SecBuffer self) -> SecBufferFlags:
        return SecBufferFlags(self.raw.BufferType & _SECBUFFER_ATTRMASK)

    def dangerous_get_view(SecBuffer self) -> memoryview:
        raise NotImplementedError()

def free_context_buffer(
    SecBuffer buffer not None,
) -> None:
    with nogil:
        res = FreeContextBuffer(&buffer.raw)

    if res:
        PyErr_SetFromWindowsErr(res)
