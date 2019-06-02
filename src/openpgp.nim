import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2003-2012 Free Software Foundation, Inc.
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
##  This file contains the types and prototypes for the OpenPGP
##  key and private key parsing functions.
##

##  *INDENT-OFF*

##  *INDENT-ON*
##  Openpgp certificate stuff
##
## *
##  gnutls_openpgp_crt_fmt_t:
##  @GNUTLS_OPENPGP_FMT_RAW: OpenPGP certificate in raw format.
##  @GNUTLS_OPENPGP_FMT_BASE64: OpenPGP certificate in base64 format.
##
##  Enumeration of different OpenPGP key formats.
##

type
  gnutls_openpgp_crt_fmt_t* {.size: sizeof(cint).} = enum
    GNUTLS_OPENPGP_FMT_RAW, GNUTLS_OPENPGP_FMT_BASE64


const
  GNUTLS_OPENPGP_KEYID_SIZE* = 8
  GNUTLS_OPENPGP_V4_FINGERPRINT_SIZE* = 20

type
  gnutls_openpgp_keyid_t* = array[GNUTLS_OPENPGP_KEYID_SIZE, cuchar]

##  gnutls_openpgp_cert_t should be defined in gnutls.h
##
##  initializes the memory for gnutls_openpgp_crt_t struct

proc gnutls_openpgp_crt_init*(key: ptr gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_openpgp_crt_init", gnutls_import.}
##  frees all memory

proc gnutls_openpgp_crt_deinit*(key: gnutls_openpgp_crt_t) {.
    importc: "gnutls_openpgp_crt_deinit", gnutls_import.}
proc gnutls_openpgp_crt_import*(key: gnutls_openpgp_crt_t;
                               data: ptr gnutls_datum_t;
                               format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_openpgp_crt_import", gnutls_import.}
proc gnutls_openpgp_crt_export*(key: gnutls_openpgp_crt_t;
                               format: gnutls_openpgp_crt_fmt_t;
                               output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_openpgp_crt_export", gnutls_import.}
proc gnutls_openpgp_crt_export2*(key: gnutls_openpgp_crt_t;
                                format: gnutls_openpgp_crt_fmt_t;
                                `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_crt_export2", gnutls_import.}
proc gnutls_openpgp_crt_print*(cert: gnutls_openpgp_crt_t;
                              format: gnutls_certificate_print_formats_t;
                              `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_crt_print", gnutls_import.}
##  The key_usage flags are defined in gnutls.h. They are
##  the GNUTLS_KEY_* definitions.
##

#const GNUTLS_OPENPGP_MASTER_KEYID_IDX* = INT_MAX

proc gnutls_openpgp_crt_get_key_usage*(key: gnutls_openpgp_crt_t;
                                      key_usage: ptr cuint): cint {.
    importc: "gnutls_openpgp_crt_get_key_usage", gnutls_import.}
proc gnutls_openpgp_crt_get_fingerprint*(key: gnutls_openpgp_crt_t; fpr: pointer;
                                        fprlen: ptr csize): cint {.
    importc: "gnutls_openpgp_crt_get_fingerprint", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_fingerprint*(key: gnutls_openpgp_crt_t;
    idx: cuint; fpr: pointer; fprlen: ptr csize): cint {.
    importc: "gnutls_openpgp_crt_get_subkey_fingerprint", gnutls_import.}
proc gnutls_openpgp_crt_get_name*(key: gnutls_openpgp_crt_t; idx: cint; buf: cstring;
                                 sizeof_buf: ptr csize): cint {.
    importc: "gnutls_openpgp_crt_get_name", gnutls_import.}
proc gnutls_openpgp_crt_get_pk_algorithm*(key: gnutls_openpgp_crt_t;
    bits: ptr cuint): gnutls_pk_algorithm_t {.
    importc: "gnutls_openpgp_crt_get_pk_algorithm", gnutls_import.}
proc gnutls_openpgp_crt_get_version*(key: gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_openpgp_crt_get_version", gnutls_import.}
proc gnutls_openpgp_crt_get_creation_time*(key: gnutls_openpgp_crt_t): time_t {.
    importc: "gnutls_openpgp_crt_get_creation_time", gnutls_import.}
proc gnutls_openpgp_crt_get_expiration_time*(key: gnutls_openpgp_crt_t): time_t {.
    importc: "gnutls_openpgp_crt_get_expiration_time", gnutls_import.}
proc gnutls_openpgp_crt_get_key_id*(key: gnutls_openpgp_crt_t;
                                   keyid: gnutls_openpgp_keyid_t): cint {.
    importc: "gnutls_openpgp_crt_get_key_id", gnutls_import.}
proc gnutls_openpgp_crt_check_hostname*(key: gnutls_openpgp_crt_t;
                                       hostname: cstring): cint {.
    importc: "gnutls_openpgp_crt_check_hostname", gnutls_import.}
proc gnutls_openpgp_crt_check_hostname2*(key: gnutls_openpgp_crt_t;
                                        hostname: cstring; flags: cuint): cint {.
    importc: "gnutls_openpgp_crt_check_hostname2", gnutls_import.}
proc gnutls_openpgp_crt_check_email*(key: gnutls_openpgp_crt_t; email: cstring;
                                    flags: cuint): cint {.
    importc: "gnutls_openpgp_crt_check_email", gnutls_import.}
proc gnutls_openpgp_crt_get_revoked_status*(key: gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_openpgp_crt_get_revoked_status", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_count*(key: gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_openpgp_crt_get_subkey_count", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_idx*(key: gnutls_openpgp_crt_t;
                                       keyid: gnutls_openpgp_keyid_t): cint {.
    importc: "gnutls_openpgp_crt_get_subkey_idx", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_revoked_status*(key: gnutls_openpgp_crt_t;
    idx: cuint): cint {.importc: "gnutls_openpgp_crt_get_subkey_revoked_status",
                     gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_pk_algorithm*(key: gnutls_openpgp_crt_t;
    idx: cuint; bits: ptr cuint): gnutls_pk_algorithm_t {.
    importc: "gnutls_openpgp_crt_get_subkey_pk_algorithm", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_creation_time*(key: gnutls_openpgp_crt_t;
    idx: cuint): time_t {.importc: "gnutls_openpgp_crt_get_subkey_creation_time",
                       gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_expiration_time*(key: gnutls_openpgp_crt_t;
    idx: cuint): time_t {.importc: "gnutls_openpgp_crt_get_subkey_expiration_time",
                       gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_id*(key: gnutls_openpgp_crt_t; idx: cuint;
                                      keyid: gnutls_openpgp_keyid_t): cint {.
    importc: "gnutls_openpgp_crt_get_subkey_id", gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_usage*(key: gnutls_openpgp_crt_t; idx: cuint;
    key_usage: ptr cuint): cint {.importc: "gnutls_openpgp_crt_get_subkey_usage",
                              gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_pk_dsa_raw*(crt: gnutls_openpgp_crt_t;
    idx: cuint; p: ptr gnutls_datum_t; q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
    y: ptr gnutls_datum_t): cint {.importc: "gnutls_openpgp_crt_get_subkey_pk_dsa_raw",
                               gnutls_import.}
proc gnutls_openpgp_crt_get_subkey_pk_rsa_raw*(crt: gnutls_openpgp_crt_t;
    idx: cuint; m: ptr gnutls_datum_t; e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_crt_get_subkey_pk_rsa_raw", gnutls_import.}
proc gnutls_openpgp_crt_get_pk_dsa_raw*(crt: gnutls_openpgp_crt_t;
                                       p: ptr gnutls_datum_t;
                                       q: ptr gnutls_datum_t;
                                       g: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_crt_get_pk_dsa_raw", gnutls_import.}
proc gnutls_openpgp_crt_get_pk_rsa_raw*(crt: gnutls_openpgp_crt_t;
                                       m: ptr gnutls_datum_t; e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_crt_get_pk_rsa_raw", gnutls_import.}
proc gnutls_openpgp_crt_get_preferred_key_id*(key: gnutls_openpgp_crt_t;
    keyid: gnutls_openpgp_keyid_t): cint {.importc: "gnutls_openpgp_crt_get_preferred_key_id",
                                        gnutls_import.}
proc gnutls_openpgp_crt_set_preferred_key_id*(key: gnutls_openpgp_crt_t;
    keyid: gnutls_openpgp_keyid_t): cint {.importc: "gnutls_openpgp_crt_set_preferred_key_id",
                                        gnutls_import.}
##  privkey stuff.
##

proc gnutls_openpgp_privkey_init*(key: ptr gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_openpgp_privkey_init", gnutls_import.}
proc gnutls_openpgp_privkey_deinit*(key: gnutls_openpgp_privkey_t) {.
    importc: "gnutls_openpgp_privkey_deinit", gnutls_import.}
proc gnutls_openpgp_privkey_get_pk_algorithm*(key: gnutls_openpgp_privkey_t;
    bits: ptr cuint): gnutls_pk_algorithm_t {.
    importc: "gnutls_openpgp_privkey_get_pk_algorithm", gnutls_import.}
proc gnutls_openpgp_privkey_sec_param*(key: gnutls_openpgp_privkey_t): gnutls_sec_param_t {.
    importc: "gnutls_openpgp_privkey_sec_param", gnutls_import.}
proc gnutls_openpgp_privkey_import*(key: gnutls_openpgp_privkey_t;
                                   data: ptr gnutls_datum_t;
                                   format: gnutls_openpgp_crt_fmt_t;
                                   password: cstring; flags: cuint): cint {.
    importc: "gnutls_openpgp_privkey_import", gnutls_import.}
proc gnutls_openpgp_privkey_get_fingerprint*(key: gnutls_openpgp_privkey_t;
    fpr: pointer; fprlen: ptr csize): cint {.importc: "gnutls_openpgp_privkey_get_fingerprint",
                                       gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_fingerprint*(
    key: gnutls_openpgp_privkey_t; idx: cuint; fpr: pointer; fprlen: ptr csize): cint {.
    importc: "gnutls_openpgp_privkey_get_subkey_fingerprint", gnutls_import.}
proc gnutls_openpgp_privkey_get_key_id*(key: gnutls_openpgp_privkey_t;
                                       keyid: gnutls_openpgp_keyid_t): cint {.
    importc: "gnutls_openpgp_privkey_get_key_id", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_count*(key: gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_openpgp_privkey_get_subkey_count", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_idx*(key: gnutls_openpgp_privkey_t;
    keyid: gnutls_openpgp_keyid_t): cint {.importc: "gnutls_openpgp_privkey_get_subkey_idx",
                                        gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_revoked_status*(
    key: gnutls_openpgp_privkey_t; idx: cuint): cint {.
    importc: "gnutls_openpgp_privkey_get_subkey_revoked_status", gnutls_import.}
proc gnutls_openpgp_privkey_get_revoked_status*(key: gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_openpgp_privkey_get_revoked_status", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_pk_algorithm*(
    key: gnutls_openpgp_privkey_t; idx: cuint; bits: ptr cuint): gnutls_pk_algorithm_t {.
    importc: "gnutls_openpgp_privkey_get_subkey_pk_algorithm", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_expiration_time*(
    key: gnutls_openpgp_privkey_t; idx: cuint): time_t {.
    importc: "gnutls_openpgp_privkey_get_subkey_expiration_time", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_id*(key: gnutls_openpgp_privkey_t;
    idx: cuint; keyid: gnutls_openpgp_keyid_t): cint {.
    importc: "gnutls_openpgp_privkey_get_subkey_id", gnutls_import.}
proc gnutls_openpgp_privkey_get_subkey_creation_time*(
    key: gnutls_openpgp_privkey_t; idx: cuint): time_t {.
    importc: "gnutls_openpgp_privkey_get_subkey_creation_time", gnutls_import.}
proc gnutls_openpgp_privkey_export_subkey_dsa_raw*(
    pkey: gnutls_openpgp_privkey_t; idx: cuint; p: ptr gnutls_datum_t;
    q: ptr gnutls_datum_t; g: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
    x: ptr gnutls_datum_t): cint {.importc: "gnutls_openpgp_privkey_export_subkey_dsa_raw",
                               gnutls_import.}
proc gnutls_openpgp_privkey_export_subkey_rsa_raw*(
    pkey: gnutls_openpgp_privkey_t; idx: cuint; m: ptr gnutls_datum_t;
    e: ptr gnutls_datum_t; d: ptr gnutls_datum_t; p: ptr gnutls_datum_t;
    q: ptr gnutls_datum_t; u: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_privkey_export_subkey_rsa_raw", gnutls_import.}
proc gnutls_openpgp_privkey_export_dsa_raw*(pkey: gnutls_openpgp_privkey_t;
    p: ptr gnutls_datum_t; q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
    y: ptr gnutls_datum_t; x: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_privkey_export_dsa_raw", gnutls_import.}
proc gnutls_openpgp_privkey_export_rsa_raw*(pkey: gnutls_openpgp_privkey_t;
    m: ptr gnutls_datum_t; e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
    p: ptr gnutls_datum_t; q: ptr gnutls_datum_t; u: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_privkey_export_rsa_raw", gnutls_import.}
proc gnutls_openpgp_privkey_export*(key: gnutls_openpgp_privkey_t;
                                   format: gnutls_openpgp_crt_fmt_t;
                                   password: cstring; flags: cuint;
                                   output_data: pointer;
                                   output_data_size: ptr csize): cint {.
    importc: "gnutls_openpgp_privkey_export", gnutls_import.}
proc gnutls_openpgp_privkey_export2*(key: gnutls_openpgp_privkey_t;
                                    format: gnutls_openpgp_crt_fmt_t;
                                    password: cstring; flags: cuint;
                                    `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_openpgp_privkey_export2", gnutls_import.}
proc gnutls_openpgp_privkey_set_preferred_key_id*(key: gnutls_openpgp_privkey_t;
    keyid: gnutls_openpgp_keyid_t): cint {.importc: "gnutls_openpgp_privkey_set_preferred_key_id",
                                        gnutls_import.}
proc gnutls_openpgp_privkey_get_preferred_key_id*(key: gnutls_openpgp_privkey_t;
    keyid: gnutls_openpgp_keyid_t): cint {.importc: "gnutls_openpgp_privkey_get_preferred_key_id",
                                        gnutls_import.}
proc gnutls_openpgp_crt_get_auth_subkey*(crt: gnutls_openpgp_crt_t;
                                        keyid: gnutls_openpgp_keyid_t; flag: cuint): cint {.
    importc: "gnutls_openpgp_crt_get_auth_subkey", gnutls_import.}
##  Keyring stuff.
##

proc gnutls_openpgp_keyring_init*(keyring: ptr gnutls_openpgp_keyring_t): cint {.
    importc: "gnutls_openpgp_keyring_init", gnutls_import.}
proc gnutls_openpgp_keyring_deinit*(keyring: gnutls_openpgp_keyring_t) {.
    importc: "gnutls_openpgp_keyring_deinit", gnutls_import.}
proc gnutls_openpgp_keyring_import*(keyring: gnutls_openpgp_keyring_t;
                                   data: ptr gnutls_datum_t;
                                   format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_openpgp_keyring_import", gnutls_import.}
proc gnutls_openpgp_keyring_check_id*(ring: gnutls_openpgp_keyring_t;
                                     keyid: gnutls_openpgp_keyid_t; flags: cuint): cint {.
    importc: "gnutls_openpgp_keyring_check_id", gnutls_import.}
proc gnutls_openpgp_crt_verify_ring*(key: gnutls_openpgp_crt_t;
                                    keyring: gnutls_openpgp_keyring_t;
                                    flags: cuint; verify: ptr cuint): cint {.
    importc: "gnutls_openpgp_crt_verify_ring", gnutls_import.}
  ##  the output of the verification
proc gnutls_openpgp_crt_verify_self*(key: gnutls_openpgp_crt_t; flags: cuint;
                                    verify: ptr cuint): cint {.
    importc: "gnutls_openpgp_crt_verify_self", gnutls_import.}
proc gnutls_openpgp_keyring_get_crt*(ring: gnutls_openpgp_keyring_t; idx: cuint;
                                    cert: ptr gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_openpgp_keyring_get_crt", gnutls_import.}
proc gnutls_openpgp_keyring_get_crt_count*(ring: gnutls_openpgp_keyring_t): cint {.
    importc: "gnutls_openpgp_keyring_get_crt_count", gnutls_import.}
## *
##  gnutls_openpgp_recv_key_func:
##  @session: a TLS session
##  @keyfpr: key fingerprint
##  @keyfpr_length: length of key fingerprint
##  @key: output key.
##
##  A callback of this type is used to retrieve OpenPGP keys.  Only
##  useful on the server, and will only be used if the peer send a key
##  fingerprint instead of a full key.  See also
##  gnutls_openpgp_set_recv_key_function().
##
##  The variable @key must be allocated using gnutls_malloc().
##
##  Returns: On success, %GNUTLS_E_SUCCESS (zero) is returned,
##    otherwise an error code is returned.
##

type
  gnutls_openpgp_recv_key_func* = proc (session: gnutls_session_t;
                                     keyfpr: ptr cuchar; keyfpr_length: cuint;
                                     key: ptr gnutls_datum_t): cint

proc gnutls_openpgp_set_recv_key_function*(session: gnutls_session_t;
    `func`: gnutls_openpgp_recv_key_func) {.
    importc: "gnutls_openpgp_set_recv_key_function", gnutls_import.}
##  certificate authentication stuff.
##

proc gnutls_certificate_set_openpgp_key*(res: gnutls_certificate_credentials_t;
                                        crt: gnutls_openpgp_crt_t;
                                        pkey: gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_certificate_set_openpgp_key", gnutls_import.}
proc gnutls_certificate_get_openpgp_key*(res: gnutls_certificate_credentials_t;
                                        index: cuint;
                                        key: ptr gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_certificate_get_openpgp_key", gnutls_import.}
proc gnutls_certificate_get_openpgp_crt*(res: gnutls_certificate_credentials_t;
                                        index: cuint;
                                        crt_list: ptr ptr gnutls_openpgp_crt_t;
                                        crt_list_size: ptr cuint): cint {.
    importc: "gnutls_certificate_get_openpgp_crt", gnutls_import.}
proc gnutls_certificate_set_openpgp_key_file*(
    res: gnutls_certificate_credentials_t; certfile: cstring; keyfile: cstring;
    format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_key_file", gnutls_import.}
proc gnutls_certificate_set_openpgp_key_mem*(
    res: gnutls_certificate_credentials_t; cert: ptr gnutls_datum_t;
    key: ptr gnutls_datum_t; format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_key_mem", gnutls_import.}
proc gnutls_certificate_set_openpgp_key_file2*(
    res: gnutls_certificate_credentials_t; certfile: cstring; keyfile: cstring;
    subkey_id: cstring; format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_key_file2", gnutls_import.}
proc gnutls_certificate_set_openpgp_key_mem2*(
    res: gnutls_certificate_credentials_t; cert: ptr gnutls_datum_t;
    key: ptr gnutls_datum_t; subkey_id: cstring; format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_key_mem2", gnutls_import.}
proc gnutls_certificate_set_openpgp_keyring_mem*(
    c: gnutls_certificate_credentials_t; data: ptr cuchar; dlen: csize;
    format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_keyring_mem", gnutls_import.}
proc gnutls_certificate_set_openpgp_keyring_file*(
    c: gnutls_certificate_credentials_t; file: cstring;
    format: gnutls_openpgp_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_openpgp_keyring_file", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
