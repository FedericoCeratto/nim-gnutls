import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2008-2012 Free Software Foundation, Inc.
##
##  Author: Nikos Mavrogiannopoulos
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
##  Typedefs for more compatibility with older GnuTLS.

##  *INDENT-OFF*

##  *INDENT-ON*


type
  gnutls_connection_end_t* = cuint

##  Stuff deprecated in 2.x

type
  gnutls_cipher_algorithm* = gnutls_cipher_algorithm_t
  gnutls_kx_algorithm* = gnutls_kx_algorithm_t
  gnutls_mac_algorithm* = gnutls_mac_algorithm_t
  gnutls_digest_algorithm* = gnutls_digest_algorithm_t
  gnutls_compression_method* = gnutls_compression_method_t
  gnutls_connection_end* = gnutls_connection_end_t
  gnutls_x509_crt_fmt* = gnutls_x509_crt_fmt_t
  gnutls_pk_algorithm* = gnutls_pk_algorithm_t
  gnutls_sign_algorithm* = gnutls_sign_algorithm_t
  gnutls_close_request* = gnutls_close_request_t
  gnutls_certificate_request* = gnutls_certificate_request_t
  gnutls_certificate_status* = gnutls_certificate_status_t
  gnutls_session* = gnutls_session_t
  gnutls_alert_level* = gnutls_alert_level_t
  gnutls_alert_description* = gnutls_alert_description_t
  gnutls_x509_subject_alt_name* = gnutls_x509_subject_alt_name_t
  gnutls_openpgp_privkey* = gnutls_openpgp_privkey_t
  gnutls_openpgp_keyring* = gnutls_openpgp_keyring_t
  gnutls_x509_crt* = gnutls_x509_crt_t
  gnutls_x509_privkey* = gnutls_x509_privkey_t
  gnutls_x509_crl* = gnutls_x509_crl_t
  gnutls_x509_crq* = gnutls_x509_crq_t
  gnutls_certificate_credentials* = gnutls_certificate_credentials_t
  gnutls_anon_server_credentials* = gnutls_anon_server_credentials_t
  gnutls_anon_client_credentials* = gnutls_anon_client_credentials_t
  gnutls_srp_client_credentials* = gnutls_srp_client_credentials_t
  gnutls_srp_server_credentials* = gnutls_srp_server_credentials_t
  gnutls_dh_params* = gnutls_dh_params_t
  gnutls_rsa_params* = gnutls_rsa_params_t
  gnutls_params_type* = gnutls_params_type_t
  gnutls_credentials_type* = gnutls_credentials_type_t
  gnutls_certificate_type* = gnutls_certificate_type_t
  gnutls_datum* = gnutls_datum_t
  gnutls_transport_ptr* = gnutls_transport_ptr_t

##  Old verification flags

const
  GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT* = (0)

##  Old SRP alerts removed in 2.1.x because the TLS-SRP RFC was
##    modified to use the PSK alert.

const
  GNUTLS_A_MISSING_SRP_USERNAME* = GNUTLS_A_UNKNOWN_PSK_IDENTITY
  GNUTLS_A_UNKNOWN_SRP_USERNAME* = GNUTLS_A_UNKNOWN_PSK_IDENTITY

##  OpenPGP stuff renamed in 2.1.x.

const
  GNUTLS_OPENPGP_KEY* = GNUTLS_OPENPGP_CERT
  GNUTLS_OPENPGP_KEY_FINGERPRINT* = GNUTLS_OPENPGP_CERT_FINGERPRINT
  gnutls_openpgp_send_key* = gnutls_openpgp_send_cert

type
  gnutls_openpgp_key_status_t* = gnutls_openpgp_crt_status_t
  gnutls_openpgp_key_t* = gnutls_openpgp_crt_t

import openpgp

const
  gnutls_openpgp_key_init* = gnutls_openpgp_crt_init
  gnutls_openpgp_key_deinit* = gnutls_openpgp_crt_deinit
  gnutls_openpgp_key_import* = gnutls_openpgp_crt_import
  gnutls_openpgp_key_export* = gnutls_openpgp_crt_export
  gnutls_openpgp_key_get_key_usage* = gnutls_openpgp_crt_get_key_usage
  gnutls_openpgp_key_get_fingerprint* = gnutls_openpgp_crt_get_fingerprint
  gnutls_openpgp_key_get_pk_algorithm* = gnutls_openpgp_crt_get_pk_algorithm
  gnutls_openpgp_key_get_name* = gnutls_openpgp_crt_get_name
  gnutls_openpgp_key_get_version* = gnutls_openpgp_crt_get_version
  gnutls_openpgp_key_get_creation_time* = gnutls_openpgp_crt_get_creation_time
  gnutls_openpgp_key_get_expiration_time* = gnutls_openpgp_crt_get_expiration_time
  gnutls_openpgp_key_check_hostname* = gnutls_openpgp_crt_check_hostname

##  OpenPGP stuff renamed in 2.3.x.

const
  gnutls_openpgp_crt_get_id* = gnutls_openpgp_crt_get_key_id
  gnutls_openpgp_key_get_id* = gnutls_openpgp_crt_get_id

##  New better names renamed in 2.3.x, add these for backwards
##    compatibility with old poor names.

const
  GNUTLS_X509_CRT_FULL* = GNUTLS_CRT_PRINT_FULL
  GNUTLS_X509_CRT_ONELINE* = GNUTLS_CRT_PRINT_ONELINE
  GNUTLS_X509_CRT_UNSIGNED_FULL* = GNUTLS_CRT_PRINT_UNSIGNED_FULL

##  Namespace problems.

const
  LIBGNUTLS_VERSION* = GNUTLS_VERSION
  LIBGNUTLS_VERSION_MAJOR* = GNUTLS_VERSION_MAJOR
  LIBGNUTLS_VERSION_MINOR* = GNUTLS_VERSION_MINOR
  LIBGNUTLS_VERSION_PATCH* = GNUTLS_VERSION_PATCH
  LIBGNUTLS_VERSION_NUMBER* = GNUTLS_VERSION_NUMBER
  LIBGNUTLS_EXTRA_VERSION* = GNUTLS_VERSION

##  This is a very dangerous and error-prone function.
##  Use gnutls_privkey_sign_hash() instead.
##

proc gnutls_x509_privkey_sign_hash*(key: gnutls_x509_privkey_t;
                                   hash: ptr gnutls_datum_t;
                                   signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_sign_hash", gnutls_import.}
proc gnutls_openpgp_privkey_sign_hash*(key: gnutls_openpgp_privkey_t;
                                      hash: ptr gnutls_datum_t;
                                      signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_privkey_sign_hash", gnutls_import.}
##  gnutls_pubkey_get_preferred_hash_algorithm()

proc gnutls_x509_crt_get_preferred_hash_algorithm*(crt: gnutls_x509_crt_t;
    hash: ptr gnutls_digest_algorithm_t; mand: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_preferred_hash_algorithm", gnutls_import.}
##  use gnutls_privkey_sign_hash() with the GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA flag

#when defined(_ISOC99_SOURCE):
#  ##  we provide older functions for compatibility as inline functions that
#  ##  depend on gnutls_session_get_random.
#  proc gnutls_session_get_server_random*(session: gnutls_session_t): pointer {.
#      inline, importc: "gnutls_session_get_server_random", gnutls_import.}
#  proc gnutls_session_get_server_random*(session: gnutls_session_t): pointer {.
#      inline.} =
#    var rnd: gnutls_datum_t
#    gnutls_session_get_random(session, nil, addr(rnd))
#    ## doc-skip
#    return rnd.data
#
#  proc gnutls_session_get_client_random*(session: gnutls_session_t): pointer {.
#      inline, importc: "gnutls_session_get_client_random", gnutls_import.}
#  proc gnutls_session_get_client_random*(session: gnutls_session_t): pointer {.
#      inline.} =
#    var rnd: gnutls_datum_t
#    gnutls_session_get_random(session, addr(rnd), nil)
#    ## doc-skip
#    return rnd.data

proc gnutls_global_set_mem_functions*(alloc_func: gnutls_alloc_function;
                                     secure_alloc_func: gnutls_alloc_function;
                                     is_secure_func: gnutls_is_secure_function;
                                     realloc_func: gnutls_realloc_function;
                                     free_func: gnutls_free_function) {.
    importc: "gnutls_global_set_mem_functions", gnutls_import.}
##  defined in old headers - unused nevertheless

const
  GNUTLS_SUPPLEMENTAL_USER_MAPPING_DATA* = 0

##  old compression related functions

proc gnutls_compression_get*(session: gnutls_session_t): gnutls_compression_method_t {.
    importc: "gnutls_compression_get", gnutls_import.}
proc gnutls_compression_get_name*(algorithm: gnutls_compression_method_t): cstring {.
    importc: "gnutls_compression_get_name", gnutls_import.}
proc gnutls_compression_get_id*(name: cstring): gnutls_compression_method_t {.
    importc: "gnutls_compression_get_id", gnutls_import.}
proc gnutls_compression_list*(): ptr gnutls_compression_method_t {.
    importc: "gnutls_compression_list", gnutls_import.}
proc gnutls_priority_compression_list*(pcache: gnutls_priority_t;
                                      list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_compression_list", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
