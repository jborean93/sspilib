# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


cdef extern from "Windows.h":
    unsigned long _SEC_I_COMPLETE_AND_CONTINUE "SEC_I_COMPLETE_AND_CONTINUE"
    unsigned long _SEC_I_COMPLETE_NEEDED "SEC_I_COMPLETE_NEEDED"
    unsigned long _SEC_I_CONTINUE_NEEDED "SEC_I_CONTINUE_NEEDED"
    unsigned long _SEC_E_OK "SEC_E_OK"
