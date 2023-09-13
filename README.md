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

## Structure

This library is merely a wrapper around the SSPI APIs.
The functions under the `sspi` namespace expose the various SSPI functions under a more Pythonic snake_case format.
For example the [AcquireCredentialsHandle](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general) function is exposed as `sspi.acquire_credentials_handle`.

Errors are raised as a `WinError` which contains the error message as formatted by Windows and the error code.
Some of the objects and constants are exposed as Python clasess/dataclasses/enums for ease of use.
Some functions expose buffers that contain dynamically allocated memory from SSPI if requested and need to be explicitly freed if needed.
Please read through the docstring of the function that will be used to learn more about how to use them.
