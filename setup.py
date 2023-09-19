#!/usr/bin/env python

# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import ctypes
import ctypes.util
import os
import pathlib
import typing

from Cython.Build import cythonize
from setuptools import Extension, setup

SKIP_EXTENSIONS = os.environ.get("SSPI_SKIP_EXTENSIONS", "false").lower() == "true"
SKIP_MODULE_CHECK = os.environ.get("SSPI_SKIP_MODULE_CHECK", "false").lower() == "true"
CYTHON_LINETRACE = os.environ.get("SSPI_CYTHON_TRACING", "false").lower() == "true"


def make_extension(
    name: str,
    module: ctypes.CDLL,
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
    sspi_path = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Secur32.dll"
    print(f"Using {sspi_path} as SSPI module for platform checks")
    sspi = ctypes.CDLL(str(sspi_path.absolute()))

    for e in [
        "context_attributes",
        "credential_attributes",
        "credential",
        "message",
        "ntstatus",
        "security_buffer",
        "security_context",
        "security_package",
        "text",
    ]:
        name = e
        libraries = ["Secur32"]
        canary = None
        if isinstance(e, tuple):
            name = e[0]
            if len(e) > 1:
                libraries = e[1]
            if len(e) > 2:
                canary = e[2]

        ext = make_extension(
            f"sspi._{name}",
            module=sspi,
            canary=canary,
            libraries=libraries,
            define_macros=[
                ("UNICODE", "1"),
                ("_UNICODE", "1"),
                ("SECURITY_WIN32", "1"),
            ],
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
