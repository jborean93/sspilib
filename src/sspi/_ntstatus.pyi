# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum

class NtStatus(enum.IntEnum):
    """Known NtStatus return values."""

    SEC_I_COMPLETE_AND_CONTINUE = ...
    """
    The client must call :meth:`complete_auth_token`, pass the output to the
    sever and wait for a return token to process.
    """
    SEC_I_COMPLETE_NEEDED = ...
    """
    The client must finish building the message and then call
    :meth:`complete_auth_token`.
    """
    SEC_I_CONTINUE_NEEDED = ...
    """
    The client must send the output token to the server and wait for a return
    token to process.
    """
    SEC_E_OK = ...
    """
    The security context was successfully initialized.
    """
