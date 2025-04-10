#!/usr/bin/env python

# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import ctypes
import os
import pathlib
import platform
import typing

from Cython.Build import cythonize
from setuptools import Extension, setup

SKIP_EXTENSIONS = os.environ.get("SSPI_SKIP_EXTENSIONS", "false").lower() == "true"
SKIP_MODULE_CHECK = os.environ.get("SSPI_SKIP_MODULE_CHECK", "false").lower() == "true"
CYTHON_LINETRACE = os.environ.get("SSPI_CYTHON_TRACING", "false").lower() == "true"
SSPI_MAIN_LIB = os.environ.get("SSPI_MAIN_LIB", None)


def make_extension(
    name: str,
    module: ctypes.CDLL | None,
    canary: typing.Optional[str] = None,
    **kwargs: typing.Any,
) -> Extension | None:
    source = pathlib.Path("src") / (name.replace(".", os.sep) + ".pyx")

    if not SKIP_MODULE_CHECK and canary and not hasattr(module, canary):
        print(f"Skipping {source} as it is not supported by the selected SSPI implementation.")
        return None

    if not source.exists():
        raise FileNotFoundError(source)

    print(f"Compiling {source}")
    return Extension(
        name=name,
        sources=[str(source)],
        **kwargs,
    )


raw_extensions = []
if not SKIP_EXTENSIONS:
    if os.name == "nt":
        windir = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        sspi_path = str((windir / "System32" / "Secur32.dll").absolute())

        define_macros = [
            ("UNICODE", "1"),
            ("_UNICODE", "1"),
            ("SECURITY_WIN32", "1"),
            ("_SEC_WINNT_AUTH_TYPES", "1"),
        ]
        extra_compile_args = []
        sspi_lib = "Secur32"
        text_libs = []

    else:
        ext = "dylib" if platform.system() == "Darwin" else "so"
        sspi_path = f"libsspi.{ext}"

        define_macros = []
        extra_compile_args = ["-DSSPILIB_IS_LINUX"]
        sspi_lib = "sspi"
        text_libs = ["icuuc"]

    if SSPI_MAIN_LIB:
        sspi_path = SSPI_MAIN_LIB

    if SKIP_MODULE_CHECK:
        sspi = None
    else:
        print(f"Using {sspi_path} as SSPI module for platform checks")
        sspi = ctypes.CDLL(sspi_path)

    for e in [
        "context_attributes",
        "credential_attributes",
        "credential",
        "message",
        "ntstatus",
        "security_buffer",
        "security_context",
        "security_package",
        ("text", text_libs),
    ]:
        name = e
        libraries = [sspi_lib]
        canary = None
        if isinstance(e, tuple):
            name = e[0]
            if len(e) > 1:
                libraries.extend(e[1])
            if len(e) > 2:
                canary = e[2]

        ext = make_extension(
            f"sspilib.raw._{name}",
            module=sspi,
            canary=canary,
            extra_compile_args=extra_compile_args,
            libraries=libraries,
            define_macros=define_macros,
        )
        if ext:
            raw_extensions.append(ext)

setup(
    ext_modules=cythonize(
        raw_extensions,
        language_level=3,
        compiler_directives={"linetrace": CYTHON_LINETRACE},
    ),
)
