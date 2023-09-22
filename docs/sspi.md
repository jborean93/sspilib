# High-Level API

```{eval-rst}
.. py:module:: sspi
```

The high-level API contains three main classes for interacting with GSSPI:

+ [`UserCredential`](./sspi.html#sspi.UserCredential)
+ [`ClientSecurityContext`](./sspi.html#sspi.ClientSecurityContext)
+ [`ServerSecurityContext`](./sspi.html#sspi.ServerSecurityContext)

These classes inherit from the corresponding low-level API equivalents and can
be used for those same APIs if desired.

## Credentials

Currently only one high level credential type is defined. This credential can
be used to authenticate with an explicit username and password as well as
define the negotiation protocol to be used.

```{eval-rst}
.. autoapiclass:: sspi.UserCredential
    :show-inheritance:
    :members:
    :undoc-members:
```

## Security Contexts

```{eval-rst}
.. autoapiclass:: sspi.SecurityContext
    :show-inheritance:

.. autoapiclass:: sspi.ClientSecurityContext
    :show-inheritance:
    :inherited-members:
    :undoc-members:

.. autoapiclass:: sspi.ServerSecurityContext
    :show-inheritance:
    :inherited-members:
    :undoc-members:

.. autoapiclass:: sspi.UnwrapResult
    :members:
```
