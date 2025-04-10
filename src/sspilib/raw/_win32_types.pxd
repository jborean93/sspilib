# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from cpython.exc cimport PyErr_SetFromWindowsErr
from libc.stddef cimport size_t


cdef extern from "python_sspi.h":
    # PyErr_SetFromWindowsErr is Windows only, need a shim for Linux
    """
    #if defined(SSPILIB_IS_LINUX)
    PyObject *WinError;

    PyObject *PyErr_SetFromWindowsErr(int ierr)
    {
        if (WinError == NULL)
        {
            PyObject *winerror = PyImport_ImportModule("sspilib.raw._winerror");
            if (winerror == NULL)
            {
                PyErr_SetString(PyExc_RuntimeError, "Failed to import custom WindowsError.");
                return NULL;
            }
            else
            {
                WinError = PyObject_GetAttrString(winerror, "WindowsError");
                Py_XDECREF(winerror);
            }
        }

        PyObject * err_obj = PyLong_FromLong(ierr);
        PyErr_SetObject(WinError, err_obj);
        return NULL;
    }
    #endif
    """

    ctypedef void *PVOID;

    ctypedef unsigned short USHORT

    ctypedef int LONG
    ctypedef unsigned int ULONG
    ctypedef LONG SECURITY_STATUS

    ctypedef unsigned short WCHAR
    ctypedef WCHAR *LPWSTR
    ctypedef WCHAR SEC_WCHAR;

    ctypedef size_t ULONG_PTR

    cdef struct _SecHandle:
        ULONG_PTR dwLower
        ULONG_PTR dwUpper
    ctypedef _SecHandle SecHandle
    ctypedef SecHandle *PSecHandle

    ctypedef SecHandle _CredHandle "CredHandle"
    ctypedef PSecHandle PCredHandle

    ctypedef SecHandle _CtxtHandle "CtxtHandle"
    ctypedef PSecHandle PCtxtHandle

    cdef struct _SECURITY_INTEGER:
        unsigned int LowPart
        int          HighPart
    ctypedef _SECURITY_INTEGER SECURITY_INTEGER
    ctypedef SECURITY_INTEGER *PSECURITY_INTEGER
    ctypedef SECURITY_INTEGER TimeStamp
    ctypedef SECURITY_INTEGER *PTimeStamp

    cdef struct _GUID:
        unsigned int  Data1
        unsigned short Data2
        unsigned short Data3
        unsigned char  Data4[8]
    ctypedef _GUID GUID
