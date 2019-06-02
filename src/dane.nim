import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##  -*- c -*-
##  Copyright (C) 2012 KU Leuven
##
##  Author: Nikos Mavrogiannopoulos
##
##  This file is part of libdane.
##
##  libdane is free software; you can redistribute it and/or
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

## *
##  dane_cert_usage_t:
##  @DANE_CERT_USAGE_CA: CA constraint. The certificate/key
##    presented must have signed the verified key.
##  @DANE_CERT_USAGE_EE: The key or the certificate of the end
##    entity.
##  @DANE_CERT_USAGE_LOCAL_CA: The remote CA is local and possibly
##    untrusted by the verifier.
##  @DANE_CERT_USAGE_LOCAL_EE: The remote end-entity key is local
##    and possibly untrusted by the verifier (not signed by a CA).
##
##  Enumeration of different certificate usage types.
##

type
  dane_cert_usage_t* {.size: sizeof(cint).} = enum
    DANE_CERT_USAGE_CA = 0, DANE_CERT_USAGE_EE = 1, DANE_CERT_USAGE_LOCAL_CA = 2,
    DANE_CERT_USAGE_LOCAL_EE = 3


## *
##  dane_cert_type_t:
##  @DANE_CERT_X509: An X.509 certificate.
##  @DANE_CERT_PK: A public key.
##
##  Enumeration of different certificate types.
##

type
  dane_cert_type_t* {.size: sizeof(cint).} = enum
    DANE_CERT_X509 = 0, DANE_CERT_PK = 1


## *
##  dane_match_type_t:
##  @DANE_MATCH_EXACT: The full content.
##  @DANE_MATCH_SHA2_256: A SHA-256 hash of the content.
##  @DANE_MATCH_SHA2_512: A SHA-512 hash of the content.
##
##  Enumeration of different content matching types.
##

type
  dane_match_type_t* {.size: sizeof(cint).} = enum
    DANE_MATCH_EXACT = 0, DANE_MATCH_SHA2_256 = 1, DANE_MATCH_SHA2_512 = 2


## *
##  dane_query_status_t:
##  @DANE_QUERY_UNKNOWN: There was no query.
##  @DANE_QUERY_DNSSEC_VERIFIED: The query was verified using DNSSEC.
##  @DANE_QUERY_BOGUS: The query has wrong DNSSEC signature.
##  @DANE_QUERY_NO_DNSSEC: The query has no DNSSEC data.
##
##  Enumeration of different certificate types.
##

type
  dane_query_status_t* {.size: sizeof(cint).} = enum
    DANE_QUERY_UNKNOWN = 0, DANE_QUERY_DNSSEC_VERIFIED, DANE_QUERY_BOGUS,
    DANE_QUERY_NO_DNSSEC
  dane_state_t* = ptr dane_state_st
  dane_query_st = object
  dane_query_t* = ptr dane_query_st


## *
##  dane_state_flags_t:
##  @DANE_F_IGNORE_LOCAL_RESOLVER: Many systems are not DNSSEC-ready. In that case the local resolver is ignored, and a direct recursive resolve occurs.
##  @DANE_F_INSECURE: Ignore any DNSSEC signature verification errors.
##  @DANE_F_IGNORE_DNSSEC: Do not try to initialize DNSSEC as we will not use it (will then not try to load the DNSSEC root certificate).  Useful if the TLSA data does not come from DNS.
##
##  Enumeration of different verification flags.
##

type
  dane_state_flags_t* {.size: sizeof(cint).} = enum
    DANE_F_IGNORE_LOCAL_RESOLVER = 1, DANE_F_INSECURE = 2, DANE_F_IGNORE_DNSSEC = 4


proc dane_state_init*(s: ptr dane_state_t; flags: cuint): cint {.
    importc: "dane_state_init", gnutls_import.}
proc dane_state_set_dlv_file*(s: dane_state_t; file: cstring): cint {.
    importc: "dane_state_set_dlv_file", gnutls_import.}
proc dane_state_deinit*(s: dane_state_t) {.importc: "dane_state_deinit", gnutls_import.}
proc dane_raw_tlsa*(s: dane_state_t; r: ptr dane_query_t; dane_data: cstringArray;
                   dane_data_len: ptr cint; secure: cint; bogus: cint): cint {.
    importc: "dane_raw_tlsa", gnutls_import.}
proc dane_query_tlsa*(s: dane_state_t; r: ptr dane_query_t; host: cstring;
                     proto: cstring; port: cuint): cint {.importc: "dane_query_tlsa",
    gnutls_import.}
proc dane_query_status*(q: dane_query_t): dane_query_status_t {.
    importc: "dane_query_status", gnutls_import.}
proc dane_query_entries*(q: dane_query_t): cuint {.importc: "dane_query_entries",
    gnutls_import.}
proc dane_query_data*(q: dane_query_t; idx: cuint; usage: ptr cuint; `type`: ptr cuint;
                     match: ptr cuint; data: ptr gnutls_datum_t): cint {.
    importc: "dane_query_data", gnutls_import.}
proc dane_query_to_raw_tlsa*(q: dane_query_t; data_entries: ptr cuint;
                            dane_data: ptr cstringArray;
                            dane_data_len: ptr ptr cint; secure: ptr cint;
                            bogus: ptr cint): cint {.
    importc: "dane_query_to_raw_tlsa", gnutls_import.}
proc dane_query_deinit*(q: dane_query_t) {.importc: "dane_query_deinit", gnutls_import.}
proc dane_cert_type_name*(`type`: dane_cert_type_t): cstring {.
    importc: "dane_cert_type_name", gnutls_import.}
proc dane_match_type_name*(`type`: dane_match_type_t): cstring {.
    importc: "dane_match_type_name", gnutls_import.}
proc dane_cert_usage_name*(usage: dane_cert_usage_t): cstring {.
    importc: "dane_cert_usage_name", gnutls_import.}
## *
##  dane_verify_flags_t:
##  @DANE_VFLAG_FAIL_IF_NOT_CHECKED: If irrelevant to this certificate DANE entries are received fail instead of succeeding.
##  @DANE_VFLAG_ONLY_CHECK_EE_USAGE: The provided certificates will be verified only against any EE field. Combine with %DANE_VFLAG_FAIL_IF_NOT_CHECKED to fail if EE entries are not present.
##  @DANE_VFLAG_ONLY_CHECK_CA_USAGE: The provided certificates will be verified only against any CA field. Combine with %DANE_VFLAG_FAIL_IF_NOT_CHECKED to fail if CA entries are not present.
##
##  Enumeration of different verification status flags.
##

type
  dane_verify_flags_t* {.size: sizeof(cint).} = enum
    DANE_VFLAG_FAIL_IF_NOT_CHECKED = 1, DANE_VFLAG_ONLY_CHECK_EE_USAGE = 1 shl 1,
    DANE_VFLAG_ONLY_CHECK_CA_USAGE = 1 shl 2


## *
##  dane_verify_status_t:
##  @DANE_VERIFY_CA_CONSTRAINTS_VIOLATED: The CA constraints were violated.
##  @DANE_VERIFY_CERT_DIFFERS: The certificate obtained via DNS differs.
##  @DANE_VERIFY_UNKNOWN_DANE_INFO: No known DANE data was found in the DNS record.
##
##  Enumeration of different verification status flags.
##

type
  dane_verify_status_t* {.size: sizeof(cint).} = enum
    DANE_VERIFY_CA_CONSTRAINTS_VIOLATED = 1, DANE_VERIFY_CERT_DIFFERS = 1 shl 1,
    DANE_VERIFY_UNKNOWN_DANE_INFO = 1 shl 2


const
  DANE_VERIFY_CA_CONSTRAINS_VIOLATED* = DANE_VERIFY_CA_CONSTRAINTS_VIOLATED
  DANE_VERIFY_NO_DANE_INFO* = DANE_VERIFY_UNKNOWN_DANE_INFO

proc dane_verification_status_print*(status: cuint; `out`: ptr gnutls_datum_t;
                                    flags: cuint): cint {.
    importc: "dane_verification_status_print", gnutls_import.}
proc dane_verify_crt_raw*(s: dane_state_t; chain: ptr gnutls_datum_t;
                         chain_size: cuint; chain_type: gnutls_certificate_type_t;
                         r: dane_query_t; sflags: cuint; vflags: cuint;
                         verify: ptr cuint): cint {.importc: "dane_verify_crt_raw",
    gnutls_import.}
proc dane_verify_crt*(s: dane_state_t; chain: ptr gnutls_datum_t; chain_size: cuint;
                     chain_type: gnutls_certificate_type_t; hostname: cstring;
                     proto: cstring; port: cuint; sflags: cuint; vflags: cuint;
                     verify: ptr cuint): cint {.importc: "dane_verify_crt",
    gnutls_import.}
proc dane_verify_session_crt*(s: dane_state_t; session: gnutls_session_t;
                             hostname: cstring; proto: cstring; port: cuint;
                             sflags: cuint; vflags: cuint; verify: ptr cuint): cint {.
    importc: "dane_verify_session_crt", gnutls_import.}
proc dane_strerror*(error: cint): cstring {.importc: "dane_strerror", gnutls_import.}
const
  DANE_E_SUCCESS* = 0
  DANE_E_INITIALIZATION_ERROR* = -1
  DANE_E_RESOLVING_ERROR* = -2
  DANE_E_NO_DANE_DATA* = -3
  DANE_E_RECEIVED_CORRUPT_DATA* = -4
  DANE_E_INVALID_DNSSEC_SIG* = -5
  DANE_E_NO_DNSSEC_SIG* = -6
  DANE_E_MEMORY_ERROR* = -7
  DANE_E_REQUESTED_DATA_NOT_AVAILABLE* = -8
  DANE_E_INVALID_REQUEST* = -9
  DANE_E_PUBKEY_ERROR* = -10
  DANE_E_NO_CERT* = -11
  DANE_E_FILE_ERROR* = -12
  DANE_E_CERT_ERROR* = -13
  DANE_E_UNKNOWN_DANE_DATA* = -14
