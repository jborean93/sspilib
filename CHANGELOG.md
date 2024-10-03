# Changelog

## 0.2.0 - 2024-10-03

+ **Breaking Change** - The constructor arguments for `sspi.ClientSecurityContext` and `sspi.SeverSecurityContext` have made the `credential` argument non-optional and moved to the first positional argument
  + This is in reflection of the `credential` actually being mandatory
+ Update documentation for `accept_security_context` and `initialize_security_context` to properly reflect that the credential must be specified on the first call to those functions
+ Update `sspi-rs` to `0.13.0`
+ Require Python 3.8 or newer (dropped 3.7)

## 0.1.0 - 2023-10-04

First official release of the `sspilib` Python module.
This includes both the high and low level API used for interacting with SSPI.
As well as Windows support, there is experimental Linux and macOS support using [sspi-rs](https://github.com/Devolutions/sspi-rs) as the SSPI implementation that ships with the wheels on those platforms.
