# Python SSPI Library

[![Test workflow](https://github.com/jborean93/sspilib/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/sspilib/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/sspilib.svg)](https://badge.fury.io/py/sspilib)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/sspilib/blob/main/LICENSE)

This library provides Python functions that wraps the Windows SSPI API.
It is designed to be both a high and low level interface that other libraries can easily leverage to use with SSPI integration.
The high level interface is under the `sspilib` namespace whereas the low-level interface is under the `sspilib.raw` interface.

## Requirements

* Python 3.9+

More requirements are needed to compile the code from scratch but this library is shipped as a wheel so it isn't mandatory for installation.

## Installation

Simply run:

```bash
pip install sspilib
```

To install from source run the following:

```bash
git clone https://github.com/jborean93/sspilib.git
python -m pip install build
python -m build
pip install dist/sspilib-*.whl
```

## Development

To run the tests or make changes to this repo run the following:

```bash
git clone https://github.com/jborean93/sspilib.git
pip install -r requirements-dev.txt
pre-commit install

python -m pip install -e .

# Can compile the sspi extensions on an adhoc basis
# python setup.py build_ext --inplace
```

From there an editor like VSCode can be used to make changes and run the test suite.
To recompile the Cython files after a change run the `build_ext --inplace` command.

If building on Linux or macOS, a version of `libsspi` from [sspi-rs](https://github.com/Devolutions/sspi-rs) must be compiled with rust.
A copy of `libicuuc` alongside its headers must be present during compile time.
To compile `sspi-rs`, download the git repository and run the following.

```bash
cargo build \
    --package sspi-ffi \
    --release

export LD_LIBRARY_PATH="${PWD}/target/release"
export LIBRARY_PATH="${PWD}/target/release"
```

## Structure

This library is merely a wrapper around the SSPI APIs.
The high level API under `sspilib` exposes an easier to use Python API for SSPI.
The functions under the `sspilib.raw` namespace expose the various SSPI functions under a more Pythonic snake_case format.
For example the [AcquireCredentialsHandle](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general) function is exposed as `sspilib.raw.acquire_credentials_handle`.

Errors are raised as a `WindowsError` which contains the error message as formatted by Windows and the error code.
For non-Windows hosts there is a compatible `sspilib.WindowsError` class that is structured like the Windows only `WindowsError` builtin.
Some of the objects and constants are exposed as Python classes/dataclasses/enums for ease of use.
Please read through the docstring of the function that will be used to learn more about how to use them.

### Client Authentication Example

Here is a basic example of how to use this library for client authentication:

```python
import sspilib

cred = sspilib.UserCredential(
    "username@DOMAIN.COM",
    "password",
)

ctx = sspilib.ClientSecurityContext(
    credential=cred,
    target_name="host/server.domain.com",
)

in_token = None
while not ctx.complete:
    out_token = ctx.step(in_token)
    if not out_token:
        break

    # exchange_with_server() is a function that sends the out_token to the
    # server we are authenticating with. How this works depends on the app
    # protocol being used, e.g. HTTP, sockets, LDAP, etc.
    in_token = exchange_with_server(out_token)

# Once authenticated we can wrap messages when talking to the server. The final
# message being sent is dependent on the application protocol
secret = b"secret data"

wrapped_secret = ctx.wrap(secret)
server_enc_resp = exchange_with_server(wrapped_secret)
server_resp = ctx.unwrap(server_enc_resp).data
```

The `UserCredential` supports more options, like selecting the authentication protocol used.
The `ClientSecurityContext` requires the credentials to use and the Service Principal Name (SPN) of the target server.
Other options can be used to control the context requested attributes, channel bindings, etc as needed.
How the tokens and wrapped data is sent is dependent on the underlying protocols used, this example just shows when to exchange the data.

## Non-Windows Support

While SSPI is a Windows only API, this package ships with `manylinux2014_x86_64`, `macosx_x86_64`, and `macosx_arm64` compatible wheels that use [sspi-rs](https://github.com/Devolutions/sspi-rs).
Support for this is experimental as all the authentication logic is contained in that external API.
The interface for `sspi-rs` is exactly the same as SSPI on Windows so the same code should theoretically be possible.
In saying this, compatibility with SSPI actual is not 100% there so use at your own risk.

It is recommended to use a library that wraps GSSAPI on non-Windows platforms like [python-gssapi](https://github.com/pythongssapi/python-gssapi).
There is no support for any other architectures on Linux except `x86_64` and as `sspi-rs` only supports glibc it cannot be used with musl based distributions like Alpine.
