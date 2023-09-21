# Copyright: (c) 2023 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

ERROR_MAP = {
    0x00090312: (
        "SEC_I_CONTINUE_NEEDED",
        "The function completed successfully, but it must be called again to complete the context.",
    ),
    0x00090313: ("SEC_I_COMPLETE_NEEDED", "The function completed successfully, but CompleteToken must be called."),
    0x00090314: (
        "SEC_I_COMPLETE_AND_CONTINUE",
        "The function completed successfully, but both CompleteToken and this function must be called to complete the context.",
    ),
    0x00090315: (
        "SEC_I_LOCAL_LOGON",
        "The logon was completed, but no network authority was available. The logon was made using locally known information.",
    ),
    0x00090317: ("SEC_I_CONTEXT_EXPIRED", "The context has expired and can no longer be used."),
    0x00090320: (
        "SEC_I_INCOMPLETE_CREDENTIALS",
        "The credentials supplied were not complete and could not be verified. Additional information can be returned from the context.",
    ),
    0x00090321: ("SEC_I_RENEGOTIATE", "The context data must be renegotiated with the peer."),
    0x00090323: ("SEC_I_NO_LSA_CONTEXT", "There is no LSA mode context associated with this context."),
    0x0009035C: (
        "SEC_I_SIGNATURE_NEEDED",
        "A signature operation must be performed before the user can authenticate.",
    ),
    0x80090300: ("SEC_E_INSUFFICIENT_MEMORY", "Not enough memory is available to complete this request."),
    0x80090301: ("SEC_E_INVALID_HANDLE", "The handle specified is invalid."),
    0x80090302: ("SEC_E_UNSUPPORTED_FUNCTION", "The function requested is not supported."),
    0x80090303: ("SEC_E_TARGET_UNKNOWN", "The specified target is unknown or unreachable."),
    0x80090304: ("SEC_E_INTERNAL_ERROR", "The Local Security Authority (LSA) cannot be contacted."),
    0x80090305: ("SEC_E_SECPKG_NOT_FOUND", "The requested security package does not exist."),
    0x80090306: ("SEC_E_NOT_OWNER", "The caller is not the owner of the desired credentials."),
    0x80090307: ("SEC_E_CANNOT_INSTALL", "The security package failed to initialize and cannot be installed."),
    0x80090308: ("SEC_E_INVALID_TOKEN", "The token supplied to the function is invalid."),
    0x80090309: (
        "SEC_E_CANNOT_PACK",
        "The security package is not able to marshal the logon buffer, so the logon attempt has failed.",
    ),
    0x8009030A: (
        "SEC_E_QOP_NOT_SUPPORTED",
        "The per-message quality of protection is not supported by the security package.",
    ),
    0x8009030B: ("SEC_E_NO_IMPERSONATION", "The security context does not allow impersonation of the client."),
    0x8009030C: ("SEC_E_LOGON_DENIED", "The logon attempt failed."),
    0x8009030D: ("SEC_E_UNKNOWN_CREDENTIALS", "The credentials supplied to the package were not recognized."),
    0x8009030E: ("SEC_E_NO_CREDENTIALS", "No credentials are available in the security package."),
    0x8009030F: ("SEC_E_MESSAGE_ALTERED", "The message or signature supplied for verification has been altered."),
    0x80090310: ("SEC_E_OUT_OF_SEQUENCE", "The message supplied for verification is out of sequence."),
    0x80090311: ("SEC_E_NO_AUTHENTICATING_AUTHORITY", "No authority could be contacted for authentication."),
    0x80090316: ("SEC_E_BAD_PKGID", "The requested security package does not exist."),
    0x80090317: ("SEC_E_CONTEXT_EXPIRED", "The context has expired and can no longer be used."),
    0x80090318: ("SEC_E_INCOMPLETE_MESSAGE", "The supplied message is incomplete. The signature was not verified."),
    0x80090320: (
        "SEC_E_INCOMPLETE_CREDENTIALS",
        "The credentials supplied were not complete and could not be verified. The context could not be initialized.",
    ),
    0x80090321: ("SEC_E_BUFFER_TOO_SMALL", "The buffers supplied to a function were too small."),
    0x80090322: ("SEC_E_WRONG_PRINCIPAL", "The target principal name is incorrect."),
    0x80090324: ("SEC_E_TIME_SKEW", "The clocks on the client and server machines are skewed."),
    0x80090325: ("SEC_E_UNTRUSTED_ROOT", "The certificate chain was issued by an authority that is not trusted."),
    0x80090326: ("SEC_E_ILLEGAL_MESSAGE", "The message received was unexpected or badly formatted."),
    0x80090327: ("SEC_E_CERT_UNKNOWN", "An unknown error occurred while processing the certificate."),
    0x80090328: ("SEC_E_CERT_EXPIRED", "The received certificate has expired."),
    0x80090329: ("SEC_E_ENCRYPT_FAILURE", "The specified data could not be encrypted."),
    0x80090330: ("SEC_E_DECRYPT_FAILURE", "The specified data could not be decrypted."),
    0x80090331: (
        "SEC_E_ALGORITHM_MISMATCH",
        "The client and server cannot communicate because they do not possess a common algorithm.",
    ),
    0x80090332: (
        "SEC_E_SECURITY_QOS_FAILED",
        "The security context could not be established due to a failure in the requested quality of service (for example, mutual authentication or delegation).",
    ),
    0x80090333: (
        "SEC_E_UNFINISHED_CONTEXT_DELETED",
        "A security context was deleted before the context was completed. This is considered a logon failure.",
    ),
    0x80090334: (
        "SEC_E_NO_TGT_REPLY",
        "The client is trying to negotiate a context and the server requires user-to-user but did not send a ticket granting ticket (TGT) reply.",
    ),
    0x80090335: (
        "SEC_E_NO_IP_ADDRESSES",
        "Unable to accomplish the requested task because the local machine does not have IP addresses.",
    ),
    0x80090336: (
        "SEC_E_WRONG_CREDENTIAL_HANDLE",
        "The supplied credential handle does not match the credential associated with the security context.",
    ),
    0x80090337: (
        "SEC_E_CRYPTO_SYSTEM_INVALID",
        "The cryptographic system or checksum function is invalid because a required function is unavailable.",
    ),
    0x80090338: ("SEC_E_MAX_REFERRALS_EXCEEDED", "The number of maximum ticket referrals has been exceeded."),
    0x80090339: (
        "SEC_E_MUST_BE_KDC",
        "The local machine must be a Kerberos domain controller (KDC), and it is not.",
    ),
    0x8009033A: (
        "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED",
        "The other end of the security negotiation requires strong cryptography, but it is not supported on the local machine.",
    ),
    0x8009033B: ("SEC_E_TOO_MANY_PRINCIPALS", "The KDC reply contained more than one principal name."),
    0x8009033C: (
        "SEC_E_NO_PA_DATA",
        "Expected to find PA data for a hint of what etype to use, but it was not found.",
    ),
    0x8009033D: (
        "SEC_E_PKINIT_NAME_MISMATCH",
        "The client certificate does not contain a valid user principal name (UPN), or does not match the client name in the logon request. Contact your administrator.",
    ),
    0x8009033E: ("SEC_E_SMARTCARD_LOGON_REQUIRED", "Smart card logon is required and was not used."),
    0x8009033F: ("SEC_E_SHUTDOWN_IN_PROGRESS", "A system shutdown is in progress."),
    0x80090340: ("SEC_E_KDC_INVALID_REQUEST", "An invalid request was sent to the KDC."),
    0x80090341: (
        "SEC_E_KDC_UNABLE_TO_REFER",
        "The KDC was unable to generate a referral for the service requested.",
    ),
    0x80090342: ("SEC_E_KDC_UNKNOWN_ETYPE", "The encryption type requested is not supported by the KDC."),
    0x80090343: (
        "SEC_E_UNSUPPORTED_PREAUTH",
        "An unsupported pre-authentication mechanism was presented to the Kerberos package.",
    ),
    0x80090345: (
        "SEC_E_DELEGATION_REQUIRED",
        "The requested operation cannot be completed. The computer must be trusted for delegation, and the current user account must be configured to allow delegation.",
    ),
    0x80090346: (
        "SEC_E_BAD_BINDINGS",
        "Client's supplied Security Support Provider Interface (SSPI) channel bindings were incorrect.",
    ),
    0x80090347: ("SEC_E_MULTIPLE_ACCOUNTS", "The received certificate was mapped to multiple accounts."),
    0x80090348: ("SEC_E_NO_KERB_KEY", "No Kerberos key was found."),
    0x80090349: ("SEC_E_CERT_WRONG_USAGE", "The certificate is not valid for the requested usage."),
    0x80090350: (
        "SEC_E_DOWNGRADE_DETECTED",
        "The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.",
    ),
    0x80090351: (
        "SEC_E_SMARTCARD_CERT_REVOKED",
        "The smart card certificate used for authentication has been revoked. Contact your system administrator. The event log might contain additional information.",
    ),
    0x80090352: (
        "SEC_E_ISSUING_CA_UNTRUSTED",
        "An untrusted certification authority (CA) was detected while processing the smart card certificate used for authentication. Contact your system administrator.",
    ),
    0x80090353: (
        "SEC_E_REVOCATION_OFFLINE_C",
        "The revocation status of the smart card certificate used for authentication could not be determined. Contact your system administrator.",
    ),
    0x80090354: (
        "SEC_E_PKINIT_CLIENT_FAILURE",
        "The smart card certificate used for authentication was not trusted. Contact your system administrator.",
    ),
    0x80090355: (
        "SEC_E_SMARTCARD_CERT_EXPIRED",
        "The smart card certificate used for authentication has expired. Contact your system administrator.",
    ),
    0x80090356: (
        "SEC_E_NO_S4U_PROT_SUPPORT",
        "The Kerberos subsystem encountered an error. A service for user protocol requests was made against a domain controller that does not support services for users.",
    ),
    0x80090357: (
        "SEC_E_CROSSREALM_DELEGATION_FAILURE",
        "An attempt was made by this server to make a Kerberos-constrained delegation request for a target outside the server's realm. This is not supported and indicates a misconfiguration on this server's allowed-to-delegate-to list. Contact your administrator.",
    ),
    0x80090358: (
        "SEC_E_REVOCATION_OFFLINE_KDC",
        "The revocation status of the domain controller certificate used for smart card authentication could not be determined. The system event log contains additional information. Contact your system administrator.",
    ),
    0x80090359: (
        "SEC_E_ISSUING_CA_UNTRUSTED_KDC",
        "An untrusted CA was detected while processing the domain controller certificate used for authentication. The system event log contains additional information. Contact your system administrator.",
    ),
    0x8009035A: (
        "SEC_E_KDC_CERT_EXPIRED",
        "The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log.",
    ),
    0x8009035B: (
        "SEC_E_KDC_CERT_REVOKED",
        "The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log.",
    ),
    0x8009035D: ("SEC_E_INVALID_PARAMETER", "One or more of the parameters passed to the function were invalid."),
    0x8009035E: (
        "SEC_E_DELEGATION_POLICY",
        "The client policy does not allow credential delegation to the target server.",
    ),
    0x8009035F: (
        "SEC_E_POLICY_NLTM_ONLY",
        "The client policy does not allow credential delegation to the target server with NLTM only authentication.",
    ),
}


class WindowsError(OSError):
    """WindowsError

    This is the Exception class that replicates WindowsError that is present
    only on Windows. It manually maps known error codes to helpful error
    messages. It is only used outside of Windows where it isn't already
    defined.

    Args:
        winerror: The SSPI HRESULT error code to raise.
    """

    def __init__(self, winerror: int) -> None:
        hresult = ((1 << 32) + winerror) if winerror < 0 else winerror
        status_id, status_msg = ERROR_MAP.get(hresult, ("UNKNOWN_ERROR_CODE", "Error is unknown"))

        strerror = f"Received SSPI Error {status_id} 0x{hresult:08X}: {status_msg}"
        super().__init__(winerror, strerror)
        self.winerror = winerror
