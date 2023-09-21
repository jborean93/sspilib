# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from ._win32_types cimport *


cdef class CtxtHandle:
    cdef _CtxtHandle raw
    cdef int _needs_free
