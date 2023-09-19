# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from sspi._win32_types cimport *


cdef extern from "Security.h":
    cdef struct _SecPkgInfoW:
        unsigned long fCapabilities
        unsigned short wVersion
        unsigned short wRPCID
        unsigned long cbMaxToken
        SEC_WCHAR *Name
        SEC_WCHAR *Comment
    ctypedef _SecPkgInfoW SecPkgInfoW
    ctypedef SecPkgInfoW *PSecPkgInfoW
