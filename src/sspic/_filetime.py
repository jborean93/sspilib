# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import datetime

EPOCH_FILETIME = 116444736000000000  # 1970-01-01 as FILETIME.


def filetime_to_datetime(
    filetime: int,
) -> datetime.datetime:
    # Expiry is 100 nanosecond intervals since 1601-01-01. It might also
    # exceed the bounds Python can represent which is ignored.
    ft_epoch_ms = (filetime - EPOCH_FILETIME) // 10
    epoch_delta = datetime.timedelta(microseconds=ft_epoch_ms)

    utc = datetime.timezone.utc
    try:
        return datetime.datetime(1970, 1, 1, tzinfo=utc) + epoch_delta
    except OverflowError:
        return datetime.datetime.fromtimestamp(0, tz=utc)
