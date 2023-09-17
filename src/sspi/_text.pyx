# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from cpython.exc cimport PyErr_SetFromWindowsErr
from cpython.mem cimport PyMem_Free
from cpython.ref cimport PyObject


cdef extern from "Python.h":
    wchar_t *PyUnicode_AsWideCharString(object unicode, Py_ssize_t *size)
    PyObject *PyUnicode_FromWideChar(const wchar_t *w, Py_ssize_t size)


cdef class WideCharString:
    # cdef wchar_t *buffer
    # cdef Py_ssize_t length

    def __cinit__(WideCharString self, str value) -> None:
        if value is None:
            buffer = NULL
            length = 0
        else:
            self.buffer = PyUnicode_AsWideCharString(value, &self.length)
            if self.buffer == NULL:
                raise MemoryError()

    def __dealloc__(WideCharString self) -> None:
        if self.buffer != NULL:
            PyMem_Free(self.buffer)

        self.buffer = NULL
        self.length = 0


cdef str wide_char_to_str(
    const wchar_t *value,
    int size = -1,
):
    if value == NULL:
        return None

    return <object>PyUnicode_FromWideChar(value, size)
