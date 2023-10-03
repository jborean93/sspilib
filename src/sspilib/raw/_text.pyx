# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from cpython.mem cimport PyMem_Free
from cpython.ref cimport PyObject


cdef extern from "python_sspi.h":
    # Linux defines wchar_t as UTF-32 whereas the APIs expect UTF-16. This
    # tries to paper over the differences with a shim.
    """
    #if defined(SSPILIB_IS_LINUX)

    #include <unicode/ustring.h>

    LPWSTR PyUnicode_AsWideCharStringShim(PyObject * unicode, Py_ssize_t *size)
    {
        Py_ssize_t utf32_size = 0;
        wchar_t * utf32_buffer = PyUnicode_AsWideCharString(unicode, &utf32_size);

        UChar * utf16_buffer = NULL;
        int32_t utf16_capacity = 0;
        while (1)
        {
            int32_t utf16_chars = 0;
            UErrorCode error_code = 0;
            u_strFromUTF32(
                utf16_buffer,
                utf16_capacity,
                &utf16_chars,
                utf32_buffer,
                utf32_size,
                &error_code
            );

            if (error_code == U_BUFFER_OVERFLOW_ERROR)
            {
                // Ensure enough length for the NULL terminator
                utf16_capacity = utf16_chars + 1;
                utf16_buffer = realloc(utf16_buffer, utf16_capacity * 2);
                continue;
            }
            else if (error_code > 0)
            {
                if (utf16_buffer != NULL)
                {
                    free(utf16_buffer);
                }
                utf16_buffer = NULL;
                break;
            }
            else
            {
                *size = utf16_chars;
                break;
            }
        }

        PyMem_Free(utf32_buffer);
        return utf16_buffer;
    }

    PyObject *PyUnicode_FromWideCharShim(const LPWSTR w, Py_ssize_t size)
    {
        // Get the number of UTF-32 codepoints needed for the input string.
        UErrorCode error_code = 0;
        int32_t utf32_size = 0;
        u_strToUTF32(
            NULL,
            0,
            &utf32_size,
            w,
            size,
            &error_code
        );
        if (error_code != U_BUFFER_OVERFLOW_ERROR)
        {
            return NULL;
        }

        // Allocate the UTF-32 buffer including the NULL terminator. As it's a
        // fixed size we can just do 4 bytes per codepoint.
        UChar32* utf32_buffer = (UChar32*)malloc((utf32_size + 1) * 4);
        if (utf32_buffer == NULL)
        {
            return NULL;
        }

        error_code = 0;
        u_strToUTF32(
            utf32_buffer,
            utf32_size + 1,
            NULL,
            w,
            size,
            &error_code
        );

        PyObject * py_str = NULL;
        if (error_code <= 0)
        {
            py_str = PyUnicode_FromWideChar(utf32_buffer, utf32_size);
        }
        free(utf32_buffer);

        return py_str;
    }

    void PyMem_FreeShim(void *p)
    {
        free(p);
    }

    #else

    LPWSTR PyUnicode_AsWideCharStringShim(PyObject * unicode, Py_ssize_t *size)
    {
        return PyUnicode_AsWideCharString(unicode, size);
    }

    PyObject *PyUnicode_FromWideCharShim(const LPWSTR w, Py_ssize_t size)
    {
        return PyUnicode_FromWideChar(w, size);
    }

    void PyMem_FreeShim(void *p)
    {
        PyMem_Free(p);
    }

    #endif
    """

    LPWSTR PyUnicode_AsWideCharStringShim(object unicode, Py_ssize_t *size)
    PyObject *PyUnicode_FromWideCharShim(const LPWSTR w, Py_ssize_t size)
    void PyMem_FreeShim(void *p)


cdef class WideCharString:
    # cdef LPWSTR raw
    # cdef Py_ssize_t length

    def __cinit__(WideCharString self, str value) -> None:
        if value is not None:
            self.raw = PyUnicode_AsWideCharStringShim(value, &self.length)
            if self.raw == NULL:
                raise MemoryError()

    def __dealloc__(WideCharString self) -> None:
        if self.raw != NULL:
            PyMem_FreeShim(self.raw)

        self.raw = NULL
        self.length = 0

cdef str wide_char_to_str(
    const LPWSTR value,
    int size = -1,
    int none_is_empty = 0,
):
    if value == NULL:
        return "" if none_is_empty else None

    return <object>PyUnicode_FromWideCharShim(value, size)
