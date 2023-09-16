# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum


class NtStatus(enum.IntEnum):
    SEC_I_COMPLETE_AND_CONTINUE = _SEC_I_COMPLETE_AND_CONTINUE
    SEC_I_COMPLETE_NEEDED = _SEC_I_COMPLETE_NEEDED
    SEC_I_CONTINUE_NEEDED = _SEC_I_CONTINUE_NEEDED
    SEC_E_OK = _SEC_E_OK

    @classmethod
    def _missing_(cls, value: object) -> typing.Optional[enum.Enum]:
        if not isinstance(value, int):
            return None

        new_member = int.__new__(cls)
        new_member._name_ = "Unknown NtStatus Value 0x{0:08X}".format(value)
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)
