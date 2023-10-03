# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import datetime
import typing as t

import sspilib.raw as raw

from ._filetime import filetime_to_datetime


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

        UserCredential(protocol="Negotiate", protocol_list["!ntlm"])

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
        cred_use = {
            "initiate": raw.CredentialUse.SECPKG_CRED_OUTBOUND,
            "accept": raw.CredentialUse.SECPKG_CRED_INBOUND,
            "both": raw.CredentialUse.SECPKG_CRED_BOTH,
        }[usage]
        temp_cred, expiry = raw.acquire_credentials_handle(
            principal=None,
            package=protocol,
            credential_use=cred_use,
            auth_data=raw.WinNTAuthIdentity(
                username=username,
                domain=domain,
                password=password,
                package_list=":".join(protocol_list) if protocol_list else None,
            ),
        )
        # Transfer ownership of the acquired cred to this instance.
        raw._credential._replace_cred_handle(temp_cred, self)

        self._expiry = filetime_to_datetime(expiry)
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
