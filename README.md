# Python SSPI Library

[![Test workflow](https://github.com/jborean93/pysspi/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/pysspi/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/sspi.svg)](https://badge.fury.io/py/sspi)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/pysspi/blob/main/LICENSE)

This library provides Python functions that wraps the Windows SSPI API.
It is designed to be a low level interface that other libraries can easily leverage to use with SSPI integeration.

## Requirements

* Python 3.8+

More requires are needed to compile the code from scratch but this library is shipped as a wheel so it isn't mandatory for installation.

## Installation

Simply run:

```bash
pip install sspi
```

To install from source run the following:

```bash
git clone https://github.com/jborean93/pysspi.git
python -m pip install build
python -m build
pip install dist/sspi-*.whl
```

## Development

To run the tests or make changes to this repo run the following:

```bash
git clone https://github.com/jborean93/pysspi.git
pip install -r requirements-dev.txt
pre-commit install

python -m pip install -e .

# Can compile the sspi extensions on an adhoc basis
# python setup.py build_ext --inplace
```

From there an editor like VSCode can be used to make changes and run the test suite.
To recompile the Cython files after a change run the `build_ext --inplace` command.

If building on Linux, a version of `libsspi.so` from [sspi-rs](https://github.com/Devolutions/sspi-rs) must be compiled with rust.

```bash
cargo build \
    --package sspi-ffi \
    --release

export LD_LIBRARY_PATH="${PWD}/target/release"
export LIBRARY_PATH="${PWD}/target/release"
```

## Structure

This library is merely a wrapper around the SSPI APIs.
The functions under the `sspi` namespace expose the various SSPI functions under a more Pythonic snake_case format.
For example the [AcquireCredentialsHandle](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general) function is exposed as `sspi.acquire_credentials_handle`.

Errors are raised as a `WinError` which contains the error message as formatted by Windows and the error code.
Some of the objects and constants are exposed as Python clasess/dataclasses/enums for ease of use.
Some functions expose buffers that contain dynamically allocated memory from SSPI if requested and need to be explicitly freed if needed.
Please read through the docstring of the function that will be used to learn more about how to use them.

## Linux Support

While SSPI is a Windows only API, this package ships with `manylinux2014_x86_64` compatible wheels that use [sspi-rs](https://github.com/Devolutions/sspi-rs).
Support for this is experimental as all the authentication logic is contained in that external API.
The interface for `sspi-rs` is exactly the same as SSPI on Windows so the same code should theoretically be possible.
In saying this, compatibility with SSPI actual is not 100% there so use at your own risk.

It is recommended to use a library that wraps GSSAPI on non-Windows platforms like [python-gssapi](https://github.com/pythongssapi/python-gssapi).
There is no support for any other architectures on Linux except `x86_64` and as `sspi-rs` only supports glibc it cannot be used with musl based distributions like Alpine.
