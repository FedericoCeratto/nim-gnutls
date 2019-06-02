import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
import x509
##
##  Copyright (C) 2011-2012 Free Software Foundation, Inc.
##
##  Author: Simon Josefsson
##
##  This file is part of GnuTLS.
##
##  The GnuTLS is free software; you can redistribute it and/or
##  modify it under the terms of the GNU Lesser General Public License
##  as published by the Free Software Foundation; either version 2.1 of
##  the License, or (at your option) any later version.
##
##  This library is distributed in the hope that it will be useful, but
##  WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##  Lesser General Public License for more details.
##
##  You should have received a copy of the GNU Lesser General Public License
##  along with this program.  If not, see <http://www.gnu.org/licenses/>
##
##
##  Online Certificate Status Protocol - RFC 2560
##

##  *INDENT-OFF*

##  *INDENT-ON*

const
  GNUTLS_OCSP_NONCE* = "1.3.6.1.5.5.7.48.1.2"

## *
##  gnutls_ocsp_print_formats_t:
##  @GNUTLS_OCSP_PRINT_FULL: Full information about OCSP request/response.
##  @GNUTLS_OCSP_PRINT_COMPACT: More compact information about OCSP request/response.
##
##  Enumeration of different OCSP printing variants.
##

type
  gnutls_ocsp_print_formats_t* {.size: sizeof(cint).} = enum
    GNUTLS_OCSP_PRINT_FULL = 0, GNUTLS_OCSP_PRINT_COMPACT = 1


## *
##  gnutls_ocsp_resp_status_t:
##  @GNUTLS_OCSP_RESP_SUCCESSFUL: Response has valid confirmations.
##  @GNUTLS_OCSP_RESP_MALFORMEDREQUEST: Illegal confirmation request
##  @GNUTLS_OCSP_RESP_INTERNALERROR: Internal error in issuer
##  @GNUTLS_OCSP_RESP_TRYLATER: Try again later
##  @GNUTLS_OCSP_RESP_SIGREQUIRED: Must sign the request
##  @GNUTLS_OCSP_RESP_UNAUTHORIZED: Request unauthorized
##
##  Enumeration of different OCSP response status codes.
##

type
  gnutls_ocsp_resp_status_t* {.size: sizeof(cint).} = enum
    GNUTLS_OCSP_RESP_SUCCESSFUL = 0, GNUTLS_OCSP_RESP_MALFORMEDREQUEST = 1,
    GNUTLS_OCSP_RESP_INTERNALERROR = 2, GNUTLS_OCSP_RESP_TRYLATER = 3,
    GNUTLS_OCSP_RESP_SIGREQUIRED = 5, GNUTLS_OCSP_RESP_UNAUTHORIZED = 6


## *
##  gnutls_ocsp_cert_status_t:
##  @GNUTLS_OCSP_CERT_GOOD: Positive response to status inquiry.
##  @GNUTLS_OCSP_CERT_REVOKED: Certificate has been revoked.
##  @GNUTLS_OCSP_CERT_UNKNOWN: The responder doesn't know about the
##    certificate.
##
##  Enumeration of different OCSP response certificate status codes.
##

type
  gnutls_ocsp_cert_status_t* {.size: sizeof(cint).} = enum
    GNUTLS_OCSP_CERT_GOOD = 0, GNUTLS_OCSP_CERT_REVOKED = 1,
    GNUTLS_OCSP_CERT_UNKNOWN = 2


## *
##  gnutls_x509_crl_reason_t:
##  @GNUTLS_X509_CRLREASON_UNSPECIFIED: Unspecified reason.
##  @GNUTLS_X509_CRLREASON_KEYCOMPROMISE: Private key compromised.
##  @GNUTLS_X509_CRLREASON_CACOMPROMISE: CA compromised.
##  @GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED: Affiliation has changed.
##  @GNUTLS_X509_CRLREASON_SUPERSEDED: Certificate superseded.
##  @GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION: Operation has ceased.
##  @GNUTLS_X509_CRLREASON_CERTIFICATEHOLD: Certificate is on hold.
##  @GNUTLS_X509_CRLREASON_REMOVEFROMCRL: Will be removed from delta CRL.
##  @GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN: Privilege withdrawn.
##  @GNUTLS_X509_CRLREASON_AACOMPROMISE: AA compromised.
##
##  Enumeration of different reason codes.  Note that this
##  corresponds to the CRLReason ASN.1 enumeration type, and not the
##  ReasonFlags ASN.1 bit string.
##

type
  gnutls_x509_crl_reason_t* {.size: sizeof(cint).} = enum
    GNUTLS_X509_CRLREASON_UNSPECIFIED = 0, GNUTLS_X509_CRLREASON_KEYCOMPROMISE = 1,
    GNUTLS_X509_CRLREASON_CACOMPROMISE = 2,
    GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED = 3,
    GNUTLS_X509_CRLREASON_SUPERSEDED = 4,
    GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION = 5,
    GNUTLS_X509_CRLREASON_CERTIFICATEHOLD = 6,
    GNUTLS_X509_CRLREASON_REMOVEFROMCRL = 8,
    GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN = 9,
    GNUTLS_X509_CRLREASON_AACOMPROMISE = 10


##  When adding a verify failure reason update:
##  _gnutls_ocsp_verify_status_to_str()
##
## *
##  gnutls_ocsp_verify_reason_t:
##  @GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND: Signer cert not found.
##  @GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR: Signer keyusage bits incorrect.
##  @GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER: Signer is not trusted.
##  @GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM: Signature using insecure algorithm.
##  @GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE: Signature mismatch.
##  @GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED: Signer cert is not yet activated.
##  @GNUTLS_OCSP_VERIFY_CERT_EXPIRED: Signer cert has expired.
##
##  Enumeration of OCSP verify status codes, used by
##  gnutls_ocsp_resp_verify() and gnutls_ocsp_resp_verify_direct().
##

type
  gnutls_ocsp_verify_reason_t* {.size: sizeof(cint).} = enum
    GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND = 1,
    GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR = 2,
    GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER = 4,
    GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM = 8,
    GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE = 16,
    GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED = 32,
    GNUTLS_OCSP_VERIFY_CERT_EXPIRED = 64


type
  gnutls_ocsp_req_int* {.bycopy.} = object

  gnutls_ocsp_req_t* = ptr gnutls_ocsp_req_int

proc gnutls_ocsp_req_init*(req: ptr gnutls_ocsp_req_t): cint {.
    importc: "gnutls_ocsp_req_init", gnutls_import.}
proc gnutls_ocsp_req_deinit*(req: gnutls_ocsp_req_t) {.
    importc: "gnutls_ocsp_req_deinit", gnutls_import.}
proc gnutls_ocsp_req_import*(req: gnutls_ocsp_req_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_import", gnutls_import.}
proc gnutls_ocsp_req_export*(req: gnutls_ocsp_req_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_export", gnutls_import.}
proc gnutls_ocsp_req_print*(req: gnutls_ocsp_req_t;
                           format: gnutls_ocsp_print_formats_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_print", gnutls_import.}
proc gnutls_ocsp_req_get_version*(req: gnutls_ocsp_req_t): cint {.
    importc: "gnutls_ocsp_req_get_version", gnutls_import.}
proc gnutls_ocsp_req_get_cert_id*(req: gnutls_ocsp_req_t; indx: cuint;
                                 digest: ptr gnutls_digest_algorithm_t;
                                 issuer_name_hash: ptr gnutls_datum_t;
                                 issuer_key_hash: ptr gnutls_datum_t;
                                 serial_number: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_get_cert_id", gnutls_import.}
proc gnutls_ocsp_req_add_cert_id*(req: gnutls_ocsp_req_t;
                                 digest: gnutls_digest_algorithm_t;
                                 issuer_name_hash: ptr gnutls_datum_t;
                                 issuer_key_hash: ptr gnutls_datum_t;
                                 serial_number: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_add_cert_id", gnutls_import.}
proc gnutls_ocsp_req_add_cert*(req: gnutls_ocsp_req_t;
                              digest: gnutls_digest_algorithm_t;
                              issuer: gnutls_x509_crt_t; cert: gnutls_x509_crt_t): cint {.
    importc: "gnutls_ocsp_req_add_cert", gnutls_import.}
proc gnutls_ocsp_req_get_extension*(req: gnutls_ocsp_req_t; indx: cuint;
                                   oid: ptr gnutls_datum_t; critical: ptr cuint;
                                   data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_get_extension", gnutls_import.}
proc gnutls_ocsp_req_set_extension*(req: gnutls_ocsp_req_t; oid: cstring;
                                   critical: cuint; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_set_extension", gnutls_import.}
proc gnutls_ocsp_req_get_nonce*(req: gnutls_ocsp_req_t; critical: ptr cuint;
                               nonce: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_get_nonce", gnutls_import.}
proc gnutls_ocsp_req_set_nonce*(req: gnutls_ocsp_req_t; critical: cuint;
                               nonce: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_req_set_nonce", gnutls_import.}
proc gnutls_ocsp_req_randomize_nonce*(req: gnutls_ocsp_req_t): cint {.
    importc: "gnutls_ocsp_req_randomize_nonce", gnutls_import.}
type
  gnutls_ocsp_resp_int* {.bycopy.} = object

  gnutls_ocsp_resp_t* = ptr gnutls_ocsp_resp_int

proc gnutls_ocsp_resp_init*(resp: ptr gnutls_ocsp_resp_t): cint {.
    importc: "gnutls_ocsp_resp_init", gnutls_import.}
proc gnutls_ocsp_resp_deinit*(resp: gnutls_ocsp_resp_t) {.
    importc: "gnutls_ocsp_resp_deinit", gnutls_import.}
proc gnutls_ocsp_resp_import*(resp: gnutls_ocsp_resp_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_import", gnutls_import.}
proc gnutls_ocsp_resp_import2*(resp: gnutls_ocsp_resp_t; data: ptr gnutls_datum_t;
                              fmt: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_ocsp_resp_import2", gnutls_import.}
proc gnutls_ocsp_resp_export*(resp: gnutls_ocsp_resp_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_export", gnutls_import.}
proc gnutls_ocsp_resp_export2*(resp: gnutls_ocsp_resp_t; data: ptr gnutls_datum_t;
                              fmt: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_ocsp_resp_export2", gnutls_import.}
proc gnutls_ocsp_resp_print*(resp: gnutls_ocsp_resp_t;
                            format: gnutls_ocsp_print_formats_t;
                            `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_print", gnutls_import.}
proc gnutls_ocsp_resp_get_status*(resp: gnutls_ocsp_resp_t): cint {.
    importc: "gnutls_ocsp_resp_get_status", gnutls_import.}
proc gnutls_ocsp_resp_get_response*(resp: gnutls_ocsp_resp_t;
                                   response_type_oid: ptr gnutls_datum_t;
                                   response: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_response", gnutls_import.}
proc gnutls_ocsp_resp_get_version*(resp: gnutls_ocsp_resp_t): cint {.
    importc: "gnutls_ocsp_resp_get_version", gnutls_import.}
proc gnutls_ocsp_resp_get_responder*(resp: gnutls_ocsp_resp_t;
                                    dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_responder", gnutls_import.}
proc gnutls_ocsp_resp_get_responder2*(resp: gnutls_ocsp_resp_t;
                                     dn: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_ocsp_resp_get_responder2", gnutls_import.}
##  the raw key ID of the responder

const
  GNUTLS_OCSP_RESP_ID_KEY* = 1

##  the raw DN of the responder

const
  GNUTLS_OCSP_RESP_ID_DN* = 2

proc gnutls_ocsp_resp_get_responder_raw_id*(resp: gnutls_ocsp_resp_t;
    `type`: cuint; raw: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_responder_raw_id", gnutls_import.}
proc gnutls_ocsp_resp_get_produced*(resp: gnutls_ocsp_resp_t): time_t {.
    importc: "gnutls_ocsp_resp_get_produced", gnutls_import.}
proc gnutls_ocsp_resp_get_single*(resp: gnutls_ocsp_resp_t; indx: cuint;
                                 digest: ptr gnutls_digest_algorithm_t;
                                 issuer_name_hash: ptr gnutls_datum_t;
                                 issuer_key_hash: ptr gnutls_datum_t;
                                 serial_number: ptr gnutls_datum_t;
                                 cert_status: ptr cuint; this_update: ptr time_t;
                                 next_update: ptr time_t;
                                 revocation_time: ptr time_t;
                                 revocation_reason: ptr cuint): cint {.
    importc: "gnutls_ocsp_resp_get_single", gnutls_import.}
proc gnutls_ocsp_resp_get_extension*(resp: gnutls_ocsp_resp_t; indx: cuint;
                                    oid: ptr gnutls_datum_t; critical: ptr cuint;
                                    data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_extension", gnutls_import.}
proc gnutls_ocsp_resp_get_nonce*(resp: gnutls_ocsp_resp_t; critical: ptr cuint;
                                nonce: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_nonce", gnutls_import.}
proc gnutls_ocsp_resp_get_signature_algorithm*(resp: gnutls_ocsp_resp_t): cint {.
    importc: "gnutls_ocsp_resp_get_signature_algorithm", gnutls_import.}
proc gnutls_ocsp_resp_get_signature*(resp: gnutls_ocsp_resp_t;
                                    sig: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_resp_get_signature", gnutls_import.}
proc gnutls_ocsp_resp_get_certs*(resp: gnutls_ocsp_resp_t;
                                certs: ptr ptr gnutls_x509_crt_t; ncerts: ptr csize): cint {.
    importc: "gnutls_ocsp_resp_get_certs", gnutls_import.}
proc gnutls_ocsp_resp_verify_direct*(resp: gnutls_ocsp_resp_t;
                                    issuer: gnutls_x509_crt_t; verify: ptr cuint;
                                    flags: cuint): cint {.
    importc: "gnutls_ocsp_resp_verify_direct", gnutls_import.}
proc gnutls_ocsp_resp_verify*(resp: gnutls_ocsp_resp_t;
                             trustlist: gnutls_x509_trust_list_t;
                             verify: ptr cuint; flags: cuint): cint {.
    importc: "gnutls_ocsp_resp_verify", gnutls_import.}
proc gnutls_ocsp_resp_check_crt*(resp: gnutls_ocsp_resp_t; indx: cuint;
                                crt: gnutls_x509_crt_t): cint {.
    importc: "gnutls_ocsp_resp_check_crt", gnutls_import.}
proc gnutls_ocsp_resp_list_import2*(ocsps: ptr ptr gnutls_ocsp_resp_t;
                                   size: ptr cuint; resp_data: ptr gnutls_datum_t;
                                   format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_ocsp_resp_list_import2", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
