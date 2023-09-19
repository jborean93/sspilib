# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from cpython.mem cimport PyMem_Free
from cpython.ref cimport PyObject


cdef extern from "Python.h":
    Py_ssize_t PyUnicode_AsWideChar(object unicode, wchar_t *w, Py_ssize_t size)
    wchar_t *PyUnicode_AsWideCharString(object unicode, Py_ssize_t *size)
    PyObject *PyUnicode_FromWideChar(const wchar_t *w, Py_ssize_t size)


cdef class WideCharString:
    # cdef wchar_t *raw
    # cdef Py_ssize_t length

    def __cinit__(WideCharString self, str value) -> None:
        if value is not None:
            self.raw = PyUnicode_AsWideCharString(value, &self.length)
            if self.raw == NULL:
                raise MemoryError()

    def __dealloc__(WideCharString self) -> None:
        if self.raw != NULL:
            PyMem_Free(self.raw)

        self.raw = NULL
        self.length = 0


cdef str wide_char_to_str(
    const wchar_t *value,
    int size = -1,
    int none_is_empty = 0,
):
    if value == NULL:
        return "" if none_is_empty else None

    return <object>PyUnicode_FromWideChar(value, size)
