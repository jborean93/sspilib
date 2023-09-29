# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum

from ._security_buffer import SecBufferDesc
from ._security_context import CtxtHandle

class QopFlags(enum.IntFlag):
    """Quality of Protection flags for :meth:`encrypt_message`."""

    KERB_WRAP_NO_ENCRYPT = ...
    """
    Produce a header or trailer but do not encrypt the message. Note this is
    the same as ``SECQOP_WRAP_NO_ENCRYPT``.
    """
    SECQOP_WRAP_NO_ENCRYPT = ...
    """
    Produce a header or trailer but do not encrypt the message. Note this is
    the same as ``KERB_WRAP_NO_ENCRYPT``.
    """
    SECQOP_WRAP_OOB_DATA = ...
    """Send an Schannel alert message."""

def decrypt_message(
    context: CtxtHandle,
    message: SecBufferDesc,
    seq_no: int,
) -> int:
    """Decrypts a message.

    The function decrypts a message. The message buffers and encryption
    algorithms used is dependent on the security context protocol and the peer
    the output message is being exchanged with.

    The function will decrypt the message buffers in place which means the
    input bytearray/memoryview used to create the :class:`SecBuffer` will also
    be modified. Use the ``data`` property of the relevant buffer to get a copy
    of the decrypted message, otherwise use the ``count`` property to get the
    decrypted bytes length from the input buffer bytearray.

    This wraps the `DecryptMessage`_ Win32 function.

    Args:
        context: The security context used to decrypt the message.
        message: The message to decrypt.
        seq_no: The sequence number that the transport application assigned to
            the message.

    Returns:
        The package specific quality of protection value.

    .. _DecryptMessage:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
    """

def encrypt_message(
    context: CtxtHandle,
    qop: QopFlags | int,
    message: SecBufferDesc,
    seq_no: int,
) -> None:
    """Encrypts a message.

    The function encrypts a message to provider privacy. The message buffers
    and encryption algorithms used is dependent on the security context
    protocol and the peer the output message is being exchanged with.

    The function will encrypt the message buffers in place which means the
    input bytearray/memoryview used to create the :class:`SecBuffer` will also
    be modified. Use the ``data`` property of the relevant buffer to get a copy
    of the encrypted message, otherwise use the ``count`` property to get the
    encrypted bytes length from the input buffer bytearray.

    This wraps the `EncryptMessage`_ Win32 function.

    Args:
        context: The security context used to encrypt the message.
        qop: Package specific flags to indicate the quality of protection.
        message: The message to encrypt.
        seq_no: The sequence number that the transport application assigned to
            the message.

    .. _EncryptMessage:
        https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general
    """

def make_signature(
    context: CtxtHandle,
    qop: QopFlags | int,
    message: SecBufferDesc,
    seq_no: int,
) -> None:
    """Signs a message.

    The function generates a cryptographic checksum of the message, and also
    includes sequencing information to prevent message loss or insertion. The
    message buffers and cryptographic algorithms used are dependent on the
    security context protocol and the peer the output message is being
    exchanged with.

    This wraps the `MakeSignature`_ Win32 function.

    Args:
        context: The security context used to sign the message.
        qop: Package specific flags to indicate the quality of protection.
        message: The message to encrypt.
        seq_no: The sequence number that the transport application assigned to
            the message.

    .. _MakeSignature:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-makesignature
    """

def verify_signature(
    context: CtxtHandle,
    message: SecBufferDesc,
    seq_no: int,
) -> int:
    """Verifies a message.

    Verifies that a message signed by :meth:`make_signature` was received in
    the correct sequence and has not been modified. The message buffers and
    cryptographic algorithms used is dependent on the security context protocol
    and the peer the input message was from.

    This wraps the `VerifySignature`_ Win32 function.

    Args:
        context: The security context used to verify the message.
        message: The message to verify.
        seq_no: The sequence number that the transport application assigned to
            the message.

    Returns:
        The package specific quality of protection value.

    .. _VerifySignature:
        https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-verifysignature
    """
