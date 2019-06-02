import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2004-2012 Free Software Foundation, Inc.
##  Copyright (c) 2002 Andrew McDonald <andrew@mcdonald.org.uk>
##
##  This file is part of GnuTLS-EXTRA.
##
##  GnuTLS-extra is free software; you can redistribute it and/or
##  modify it under the terms of the GNU General Public License as
##  published by the Free Software Foundation; either version 3 of the
##  License, or (at your option) any later version.
##
##  GnuTLS-extra is distributed in the hope that it will be useful, but
##  WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##  General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with GnuTLS-EXTRA; if not, write to the Free Software
##  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
##  02110-1301, USA.
##
##
##  WARNING: Error functions aren't currently thread-safe
##  This file contains prototypes about the OpenSSL compatibility layer
##  in GnuTLS.  GnuTLS is not a complete replacement of OPENSSL so this
##  compatibility layer only supports limited OpenSSL functionality.
##
##  New programs should avoid using this compatibility layer, and use
##  the native GnuTLS API directly.
##

##  Extra definitions that no longer exist in gnutls.
##

const
  GNUTLS_X509_CN_SIZE* = 256
  GNUTLS_X509_C_SIZE* = 3
  GNUTLS_X509_O_SIZE* = 256
  GNUTLS_X509_OU_SIZE* = 256
  GNUTLS_X509_L_SIZE* = 256
  GNUTLS_X509_S_SIZE* = 256
  GNUTLS_X509_EMAIL_SIZE* = 256

type
  gnutls_x509_dn* {.bycopy.} = object
    common_name*: array[GNUTLS_X509_CN_SIZE, char]
    country*: array[GNUTLS_X509_C_SIZE, char]
    organization*: array[GNUTLS_X509_O_SIZE, char]
    organizational_unit_name*: array[GNUTLS_X509_OU_SIZE, char]
    locality_name*: array[GNUTLS_X509_L_SIZE, char]
    state_or_province_name*: array[GNUTLS_X509_S_SIZE, char]
    email*: array[GNUTLS_X509_EMAIL_SIZE, char]


const
  OPENSSL_VERSION_NUMBER* = (0x0090604F)
  SSLEAY_VERSION_NUMBER* = OPENSSL_VERSION_NUMBER

## #define OPENSSL_VERSION_TEXT ("GNUTLS " GNUTLS_VERSION " ")

const
  SSL_ERROR_NONE* = (0)
  SSL_ERROR_SSL* = (1)
  SSL_ERROR_WANT_READ* = (2)
  SSL_ERROR_WANT_WRITE* = (3)
  SSL_ERROR_SYSCALL* = (5)
  SSL_ERROR_ZERO_RETURN* = (6)
  SSL_FILETYPE_PEM* = (GNUTLS_X509_FMT_PEM)
  SSL_VERIFY_NONE* = (0)
  SSL_ST_OK* = (1)
  X509_V_ERR_CERT_NOT_YET_VALID* = (1)
  X509_V_ERR_CERT_HAS_EXPIRED* = (2)
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT* = (3)
  SSL_OP_ALL* = (0x000FFFFF)
  SSL_OP_NO_TLSv1* = (0x00400000)
  SSL_MODE_ENABLE_PARTIAL_WRITE* = (0x00000001)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER* = (0x00000002)
  SSL_MODE_AUTO_RETRY* = (0x00000004)

type
  X509_NAME* = gnutls_x509_dn
  X509* = gnutls_datum_t
  SSL_METHOD* {.bycopy.} = object
    priority_string*: array[256, char]
    connend*: cuint

  SSL_CIPHER* {.bycopy.} = object
    version*: gnutls_protocol_t
    cipher*: gnutls_cipher_algorithm_t
    kx*: gnutls_kx_algorithm_t
    mac*: gnutls_mac_algorithm_t
    compression*: gnutls_compression_method_t
    cert*: gnutls_certificate_type_t

  BIO* {.bycopy.} = object
    fd*: gnutls_transport_ptr_t


template X509_STORE_CTX_get_current_cert*(ctx: untyped): untyped =
  ((ctx).current_cert)

type
  SSL_CTX* {.bycopy.} = object
    `method`*: ptr SSL_METHOD
    certfile*: cstring
    certfile_type*: cint
    keyfile*: cstring
    keyfile_type*: cint
    options*: culong
    verify_callback*: proc (a1: cint; a2: ptr X509_STORE_CTX): cint
    verify_mode*: cint

  SSL* {.bycopy.} = object
    gnutls_state*: gnutls_session_t
    gnutls_cred*: gnutls_certificate_client_credentials
    ctx*: ptr SSL_CTX
    ciphersuite*: SSL_CIPHER
    last_error*: cint
    shutdown*: cint
    state*: cint
    options*: culong
    verify_callback*: proc (a1: cint; a2: ptr X509_STORE_CTX): cint
    verify_mode*: cint
    rfd*: gnutls_transport_ptr_t
    wfd*: gnutls_transport_ptr_t

  X509_STORE_CTX* {.bycopy.} = object
    ssl*: ptr SSL
    error*: cint
    cert_list*: ptr gnutls_datum_t ## #define current_cert cert_list


const
  rbio* = gnutls_session_t

type
  MD_CTX* {.bycopy.} = object
    handle*: pointer

  rsa_st* {.bycopy.} = object

  RSA* = rsa_st

const
  MD5_CTX* = MD_CTX
  RIPEMD160_CTX* = MD_CTX

template OpenSSL_add_ssl_algorithms*(): untyped =
  SSL_library_init()

template SSLeay_add_ssl_algorithms*(): untyped =
  SSL_library_init()

template SSLeay_add_all_algorithms*(): untyped =
  OpenSSL_add_all_algorithms()

template SSL_get_cipher_name*(ssl: untyped): untyped =
  SSL_CIPHER_get_name(SSL_get_current_cipher(ssl))

template SSL_get_cipher*(ssl: untyped): untyped =
  SSL_get_cipher_name(ssl)

template SSL_get_cipher_bits*(ssl, bp: untyped): untyped =
  SSL_CIPHER_get_bits(SSL_get_current_cipher(ssl), (bp))

template SSL_get_cipher_version*(ssl: untyped): untyped =
  SSL_CIPHER_get_version(SSL_get_current_cipher(ssl))

##  Library initialisation functions

proc SSL_library_init*(): cint {.importc: "SSL_library_init", gnutls_import.}
proc OpenSSL_add_all_algorithms*() {.importc: "OpenSSL_add_all_algorithms",
                                   gnutls_import.}
##  SSL_CTX structure handling

proc SSL_CTX_new*(`method`: ptr SSL_METHOD): ptr SSL_CTX {.importc: "SSL_CTX_new",
    gnutls_import.}
proc SSL_CTX_free*(ctx: ptr SSL_CTX) {.importc: "SSL_CTX_free", gnutls_import.}
proc SSL_CTX_set_default_verify_paths*(ctx: ptr SSL_CTX): cint {.
    importc: "SSL_CTX_set_default_verify_paths", gnutls_import.}
proc SSL_CTX_use_certificate_file*(ctx: ptr SSL_CTX; certfile: cstring; `type`: cint): cint {.
    importc: "SSL_CTX_use_certificate_file", gnutls_import.}
proc SSL_CTX_use_PrivateKey_file*(ctx: ptr SSL_CTX; keyfile: cstring; `type`: cint): cint {.
    importc: "SSL_CTX_use_PrivateKey_file", gnutls_import.}
proc SSL_CTX_set_verify*(ctx: ptr SSL_CTX; verify_mode: cint; verify_callback: proc (
    a1: cint; a2: ptr X509_STORE_CTX): cint) {.importc: "SSL_CTX_set_verify",
    gnutls_import.}
proc SSL_CTX_set_options*(ctx: ptr SSL_CTX; options: culong): culong {.
    importc: "SSL_CTX_set_options", gnutls_import.}
proc SSL_CTX_set_mode*(ctx: ptr SSL_CTX; mode: clong): clong {.
    importc: "SSL_CTX_set_mode", gnutls_import.}
proc SSL_CTX_set_cipher_list*(ctx: ptr SSL_CTX; list: cstring): cint {.
    importc: "SSL_CTX_set_cipher_list", gnutls_import.}
##  SSL_CTX statistics

proc SSL_CTX_sess_number*(ctx: ptr SSL_CTX): clong {.importc: "SSL_CTX_sess_number",
    gnutls_import.}
proc SSL_CTX_sess_connect*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_connect", gnutls_import.}
proc SSL_CTX_sess_connect_good*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_connect_good", gnutls_import.}
proc SSL_CTX_sess_connect_renegotiate*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_connect_renegotiate", gnutls_import.}
proc SSL_CTX_sess_accept*(ctx: ptr SSL_CTX): clong {.importc: "SSL_CTX_sess_accept",
    gnutls_import.}
proc SSL_CTX_sess_accept_good*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_accept_good", gnutls_import.}
proc SSL_CTX_sess_accept_renegotiate*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_accept_renegotiate", gnutls_import.}
proc SSL_CTX_sess_hits*(ctx: ptr SSL_CTX): clong {.importc: "SSL_CTX_sess_hits",
    gnutls_import.}
proc SSL_CTX_sess_misses*(ctx: ptr SSL_CTX): clong {.importc: "SSL_CTX_sess_misses",
    gnutls_import.}
proc SSL_CTX_sess_timeouts*(ctx: ptr SSL_CTX): clong {.
    importc: "SSL_CTX_sess_timeouts", gnutls_import.}
##  SSL structure handling

proc SSL_new*(ctx: ptr SSL_CTX): ptr SSL {.importc: "SSL_new", gnutls_import.}
proc SSL_free*(ssl: ptr SSL) {.importc: "SSL_free", gnutls_import.}
proc SSL_load_error_strings*() {.importc: "SSL_load_error_strings", gnutls_import.}
proc SSL_get_error*(ssl: ptr SSL; ret: cint): cint {.importc: "SSL_get_error",
    gnutls_import.}
proc SSL_set_fd*(ssl: ptr SSL; fd: cint): cint {.importc: "SSL_set_fd", gnutls_import.}
proc SSL_set_rfd*(ssl: ptr SSL; fd: cint): cint {.importc: "SSL_set_rfd", gnutls_import.}
proc SSL_set_wfd*(ssl: ptr SSL; fd: cint): cint {.importc: "SSL_set_wfd", gnutls_import.}
proc SSL_set_bio*(ssl: ptr SSL; rbio: ptr BIO; wbio: ptr BIO) {.importc: "SSL_set_bio",
    gnutls_import.}
proc SSL_set_connect_state*(ssl: ptr SSL) {.importc: "SSL_set_connect_state",
                                        gnutls_import.}
proc SSL_pending*(ssl: ptr SSL): cint {.importc: "SSL_pending", gnutls_import.}
proc SSL_set_verify*(ssl: ptr SSL; verify_mode: cint; verify_callback: proc (a1: cint;
    a2: ptr X509_STORE_CTX): cint) {.importc: "SSL_set_verify", gnutls_import.}
proc SSL_get_peer_certificate*(ssl: ptr SSL): ptr X509 {.
    importc: "SSL_get_peer_certificate", gnutls_import.}
##  SSL connection open/close/read/write functions

proc SSL_connect*(ssl: ptr SSL): cint {.importc: "SSL_connect", gnutls_import.}
proc SSL_accept*(ssl: ptr SSL): cint {.importc: "SSL_accept", gnutls_import.}
proc SSL_shutdown*(ssl: ptr SSL): cint {.importc: "SSL_shutdown", gnutls_import.}
proc SSL_read*(ssl: ptr SSL; buf: pointer; len: cint): cint {.importc: "SSL_read",
    gnutls_import.}
proc SSL_write*(ssl: ptr SSL; buf: pointer; len: cint): cint {.importc: "SSL_write",
    gnutls_import.}
proc SSL_want*(ssl: ptr SSL): cint {.importc: "SSL_want", gnutls_import.}
const
  SSL_NOTHING* = (1)
  SSL_WRITING* = (2)
  SSL_READING* = (3)
  SSL_X509_LOOKUP* = (4)

template SSL_want_nothing*(s: untyped): untyped =
  (SSL_want(s) == SSL_NOTHING)

template SSL_want_read*(s: untyped): untyped =
  (SSL_want(s) == SSL_READING)

template SSL_want_write*(s: untyped): untyped =
  (SSL_want(s) == SSL_WRITING)

template SSL_want_x509_lookup*(s: untyped): untyped =
  (SSL_want(s) == SSL_X509_LOOKUP)

##  SSL_METHOD functions

proc SSLv23_client_method*(): ptr SSL_METHOD {.importc: "SSLv23_client_method",
    gnutls_import.}
proc SSLv23_server_method*(): ptr SSL_METHOD {.importc: "SSLv23_server_method",
    gnutls_import.}
proc SSLv3_client_method*(): ptr SSL_METHOD {.importc: "SSLv3_client_method",
    gnutls_import.}
proc SSLv3_server_method*(): ptr SSL_METHOD {.importc: "SSLv3_server_method",
    gnutls_import.}
proc TLSv1_client_method*(): ptr SSL_METHOD {.importc: "TLSv1_client_method",
    gnutls_import.}
proc TLSv1_server_method*(): ptr SSL_METHOD {.importc: "TLSv1_server_method",
    gnutls_import.}
##  SSL_CIPHER functions

proc SSL_get_current_cipher*(ssl: ptr SSL): ptr SSL_CIPHER {.
    importc: "SSL_get_current_cipher", gnutls_import.}
proc SSL_CIPHER_get_name*(cipher: ptr SSL_CIPHER): cstring {.
    importc: "SSL_CIPHER_get_name", gnutls_import.}
proc SSL_CIPHER_get_bits*(cipher: ptr SSL_CIPHER; bits: ptr cint): cint {.
    importc: "SSL_CIPHER_get_bits", gnutls_import.}
proc SSL_CIPHER_get_version*(cipher: ptr SSL_CIPHER): cstring {.
    importc: "SSL_CIPHER_get_version", gnutls_import.}
proc SSL_CIPHER_description*(cipher: ptr SSL_CIPHER; buf: cstring; size: cint): cstring {.
    importc: "SSL_CIPHER_description", gnutls_import.}
##  X509 functions

proc X509_get_subject_name*(cert: ptr X509): ptr X509_NAME {.
    importc: "X509_get_subject_name", gnutls_import.}
proc X509_get_issuer_name*(cert: ptr X509): ptr X509_NAME {.
    importc: "X509_get_issuer_name", gnutls_import.}
proc X509_NAME_oneline*(name: ptr gnutls_x509_dn; buf: cstring; len: cint): cstring {.
    importc: "X509_NAME_oneline", gnutls_import.}
proc X509_free*(cert: ptr X509) {.importc: "X509_free", gnutls_import.}
##  BIO functions

proc BIO_get_fd*(gnutls_state: gnutls_session_t; fd: ptr cint) {.
    importc: "BIO_get_fd", gnutls_import.}
proc BIO_new_socket*(sock: cint; close_flag: cint): ptr BIO {.
    importc: "BIO_new_socket", gnutls_import.}
##  error handling

proc ERR_get_error*(): culong {.importc: "ERR_get_error", gnutls_import.}
proc ERR_error_string*(e: culong; buf: cstring): cstring {.
    importc: "ERR_error_string", gnutls_import.}
##  RAND functions

proc RAND_status*(): cint {.importc: "RAND_status", gnutls_import.}
proc RAND_seed*(buf: pointer; num: cint) {.importc: "RAND_seed", gnutls_import.}
proc RAND_bytes*(buf: ptr cuchar; num: cint): cint {.importc: "RAND_bytes", gnutls_import.}
proc RAND_pseudo_bytes*(buf: ptr cuchar; num: cint): cint {.
    importc: "RAND_pseudo_bytes", gnutls_import.}
proc RAND_file_name*(buf: cstring; len: csize): cstring {.importc: "RAND_file_name",
    gnutls_import.}
proc RAND_load_file*(name: cstring; maxbytes: clong): cint {.
    importc: "RAND_load_file", gnutls_import.}
proc RAND_write_file*(name: cstring): cint {.importc: "RAND_write_file", gnutls_import.}
proc RAND_egd_bytes*(path: cstring; bytes: cint): cint {.importc: "RAND_egd_bytes",
    gnutls_import.}
template RAND_egd*(p: untyped): untyped =
  RAND_egd_bytes((p), 255)

##  message digest functions

const
  MD5_DIGEST_LENGTH* = 16

proc MD5_Init*(ctx: ptr MD5_CTX) {.importc: "MD5_Init", gnutls_import.}
proc MD5_Update*(ctx: ptr MD5_CTX; buf: pointer; len: cint) {.importc: "MD5_Update",
    gnutls_import.}
proc MD5_Final*(md: ptr cuchar; ctx: ptr MD5_CTX) {.importc: "MD5_Final", gnutls_import.}
proc MD5*(buf: ptr cuchar; len: culong; md: ptr cuchar): ptr cuchar {.importc: "MD5",
    gnutls_import.}
proc RIPEMD160_Init*(ctx: ptr RIPEMD160_CTX) {.importc: "RIPEMD160_Init", gnutls_import.}
proc RIPEMD160_Update*(ctx: ptr RIPEMD160_CTX; buf: pointer; len: cint) {.
    importc: "RIPEMD160_Update", gnutls_import.}
proc RIPEMD160_Final*(md: ptr cuchar; ctx: ptr RIPEMD160_CTX) {.
    importc: "RIPEMD160_Final", gnutls_import.}
proc RIPEMD160*(buf: ptr cuchar; len: culong; md: ptr cuchar): ptr cuchar {.
    importc: "RIPEMD160", gnutls_import.}
