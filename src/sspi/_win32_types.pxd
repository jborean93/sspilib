# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stddef cimport size_t, wchar_t


cdef extern from "Windows.h":
    ctypedef void *PVOID;

    ctypedef unsigned short USHORT

    ctypedef long LONG
    ctypedef unsigned long ULONG
    ctypedef LONG SECURITY_STATUS

    ctypedef wchar_t WCHAR
    ctypedef WCHAR *LPWSTR
    ctypedef WCHAR SEC_WCHAR;

    ctypedef size_t ULONG_PTR

    cdef struct _SecHandle:
        ULONG_PTR dwLower
        ULONG_PTR dwUpper
    ctypedef _SecHandle SecHandle
    ctypedef SecHandle *PSecHandle

    ctypedef SecHandle CredHandle
    ctypedef PSecHandle PCredHandle

    ctypedef SecHandle CtxtHandle
    ctypedef PSecHandle PCtxtHandle

    cdef struct _SECURITY_INTEGER:
        unsigned long LowPart
        long          HighPart
    ctypedef _SECURITY_INTEGER SECURITY_INTEGER
    ctypedef SECURITY_INTEGER *PSECURITY_INTEGER
    ctypedef SECURITY_INTEGER TimeStamp
    ctypedef SECURITY_INTEGER *PTimeStamp
