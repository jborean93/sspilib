# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import datetime
import pathlib
import typing as t

import sspilib.raw as raw

from ._filetime import filetime_to_datetime


def _acquire_credential(
    credential: raw.CredHandle,
    protocol: str,
    usage: t.Literal["initiate", "accept", "both"],
    identity: raw.AuthIdentity,
) -> datetime.datetime:
    cred_use = {
        "initiate": raw.CredentialUse.SECPKG_CRED_OUTBOUND,
        "accept": raw.CredentialUse.SECPKG_CRED_INBOUND,
        "both": raw.CredentialUse.SECPKG_CRED_BOTH,
    }[usage]

    temp_cred, expiry = raw.acquire_credentials_handle(
        principal=None,
        package=protocol,
        credential_use=cred_use,
        auth_data=identity,
    )
    # Transfer ownership of the acquired cred to higher level instance.
    raw._credential._replace_cred_handle(temp_cred, credential)

    return filetime_to_datetime(expiry)


class KeytabCredential(raw.CredHandle):
    """A keytab credential.

    This represents an SSPI credential backed by a keytab. It can be used as a
    credential for an initiator or acceptor using a keytab file created by tools
    like ktpass.exe, ktutil from MIT krb5, or Heimdal. The username should be
    the principal in th keytab you want to use. If using a username in the UPN
    format ``user@DOMAIN.COM``, do not specify anything for the domain argument.

    If the keytab argument is a str or :class:`pathlib.Path` value it is treated
    as the path to a keytab file which will be read. If the argument is a bytes,
    bytearray, or memoryview value it is treated as the raw keytab data and will
    be used as is.

    The usage must be set to ``initiate`` for client credentials, ``accept``
    for server credentials, or ``both`` for both a client and server.

    The protocol_list can be set to a list of protocols that the ``Negotiate``
    protocol can use. To stop a protocol from being used, prefix the value with
    ``!``, for example the following will turn off NTLM being negotiated:

        UserCredential(protocol="Negotiate", protocol_list=["!ntlm"])

    This class is designed to be a high level overlay on top of the
    :class:`sspilib.raw.CredHandle` class. It can be used as a credential for
    both the high level API as well as te low level API if more complex
    scenarios are needed.

    Args:
        username: The username/principal to authenticate as.
        keytab: The keytab data or str/pathlib.Path for the path to a keytab
            file.
        domain: The domain the user belongs to.
        protocol: The security protocol this credential can use for
            authentication.
        usage: How the credentials will be used.
        protocol_list: A list of protocols to allow or deny.
    """

    def __init__(
        self,
        username: str,
        keytab: bytes | bytearray | memoryview | str | pathlib.Path,
        domain: str | None = None,
        protocol: str = "Negotiate",
        usage: t.Literal["initiate", "accept", "both"] = "initiate",
        *,
        protocol_list: list[str] | None = None,
    ) -> None:
        if isinstance(keytab, (str, pathlib.Path)):
            with open(keytab, mode="rb") as keytab_fd:
                keytab = keytab_fd.read()

        identity = raw.WinNTAuthIdentityPackedCredential(
            credential_type=raw.WinNTAuthCredentialType.SEC_WINNT_AUTH_DATA_TYPE_KEYTAB,
            credential=keytab,
            username=username,
            domain=domain,
            package_list=":".join(protocol_list) if protocol_list else None,
        )
        self._expiry = _acquire_credential(self, protocol, usage, identity)

        self._protocol = protocol
        self._username = username
        if domain:
            self._username = f"{domain}\\{self._username}"

    def __str__(self) -> str:
        return f"{self.username} - {self.protocol}"

    @property
    def expiry(self) -> datetime.datetime:
        """The time when this credential expires."""
        return self._expiry

    @property
    def protocol(self) -> str:
        """The security protocol this credential can use."""
        return self._protocol

    @property
    def username(self) -> str:
        """The username this credential is for."""
        return self._username


class UserCredential(raw.CredHandle):
    """A user credential.

    This represents an SSPI credential backed by a username and password. It
    can also be used to specify the security protocol used, defaults to
    ``Negotiate``.

    If using a username in the UPN format ``user@DOMAIN.COM``, do not specify
    anything for the domain argument.

    The usage must be set to ``initiate`` for client credentials, ``accept``
    for server credentials, or ``both`` for both a client and server.

    The protocol_list can be set to a list of protocols that the ``Negotiate``
    protocol can use. To stop a protocol from being used, prefix the value with
    ``!``, for example the following will turn off NTLM being negotiated:

        UserCredential(protocol="Negotiate", protocol_list=["!ntlm"])

    This class is designed to be a high level overlay on top of the
    :class:`sspilib.raw.CredHandle` class. It can be used as a credential for both
    the high level API as well as te low level API if more complex scenarios
    are needed.

    Args:
        username: The username to authenticate as.
        password: The password for the user specified.
        domain: The domain the user belongs to.
        protocol: The security protocol this credential can use for
            authentication.
        usage: How the credentials will be used.
        protocol_list: A list of protocols to allow or deny.
    """

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        protocol: str = "Negotiate",
        usage: t.Literal["initiate", "accept", "both"] = "initiate",
        *,
        protocol_list: list[str] | None = None,
    ) -> None:
        identity = raw.WinNTAuthIdentity(
            username=username,
            domain=domain,
            password=password,
            package_list=":".join(protocol_list) if protocol_list else None,
        )
        self._expiry = _acquire_credential(self, protocol, usage, identity)

        self._protocol = protocol
        self._username = username or "CurrentUser"
        if domain:
            self._username = f"{domain}\\{self._username}"

    def __str__(self) -> str:
        return f"{self.username} - {self.protocol}"

    @property
    def expiry(self) -> datetime.datetime:
        """The time when this credential expires."""
        return self._expiry

    @property
    def protocol(self) -> str:
        """The security protocol this credential can use."""
        return self._protocol

    @property
    def username(self) -> str:
        """The username this credential is for."""
        return self._username
