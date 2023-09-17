# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from ._win32_types cimport *


cdef class SecurityContext:
    cdef CtxtHandle raw
    cdef TimeStamp raw_expiry
    cdef int _needs_free
