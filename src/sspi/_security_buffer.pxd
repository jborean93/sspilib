# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from sspi._win32_types cimport *


cdef extern from "Security.h":
    cdef struct _SecBuffer:
        unsigned long cbBuffer
        unsigned long BufferType
        void *pvBuffer
    ctypedef _SecBuffer *PSecBuffer

    cdef struct _SecBufferDesc:
        unsigned long ulVersion
        unsigned long cBuffers
        PSecBuffer pBuffers
    ctypedef _SecBufferDesc *PSecBufferDesc

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-freecontextbuffer
    SECURITY_STATUS FreeContextBuffer(
        PVOID pvContextBuffer
    ) nogil


cdef class SecBufferDesc:
    cdef _SecBufferDesc raw
    cdef list[SecBuffer] _buffers

    cdef void mark_as_allocated(SecBufferDesc self)
    cdef void sync_buffers(SecBufferDesc self)

cdef class SecBuffer:
    cdef _SecBuffer raw
    cdef unsigned char[:] _buffer
    cdef int _needs_free
