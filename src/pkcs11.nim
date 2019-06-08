import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
import x509
import openpgp
##
##  Copyright (C) 2010-2012 Free Software Foundation, Inc.
##  Copyright (C) 2016-2018 Red Hat, Inc.
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

##  *INDENT-OFF*

##  *INDENT-ON*

const
  GNUTLS_PKCS11_MAX_PIN_LEN* = 32

## *
##  gnutls_pkcs11_token_callback_t:
##  @userdata: user-controlled data from gnutls_pkcs11_set_token_function().
##  @label: token label.
##  @retry: retry counter, initially 0.
##
##  Token callback function. The callback will be used to ask the user
##  to re-insert the token with given (null terminated) label.  The
##  callback should return zero if token has been inserted by user and
##  a negative error code otherwise.  It might be called multiple times
##  if the token is not detected and the retry counter will be
##  increased.
##
##  Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code
##  on error.
##
##  Since: 2.12.0
##

type
  gnutls_pkcs11_token_callback_t* = proc (userdata: pointer; label: cstring;
                                       retry: cuint): cint
  gnutls_pkcs11_obj_st* {.bycopy.} = object

  gnutls_pkcs11_obj_t* = ptr gnutls_pkcs11_obj_st

const
  GNUTLS_PKCS11_FLAG_MANUAL* = 0
  GNUTLS_PKCS11_FLAG_AUTO* = 1
  GNUTLS_PKCS11_FLAG_AUTO_TRUSTED* = (1 shl 1) ##  Automatically load trusted libraries by reading /etc/gnutls/pkcs11.conf

##  pkcs11.conf format:
##  load = /lib/xxx-pkcs11.so
##  load = /lib/yyy-pkcs11.so
##

proc gnutls_pkcs11_init*(flags: cuint; deprecated_config_file: cstring): cint {.
    importc: "gnutls_pkcs11_init", gnutls_import.}
proc gnutls_pkcs11_reinit*(): cint {.importc: "gnutls_pkcs11_reinit", gnutls_import.}
proc gnutls_pkcs11_deinit*() {.importc: "gnutls_pkcs11_deinit", gnutls_import.}
proc gnutls_pkcs11_set_token_function*(fn: gnutls_pkcs11_token_callback_t;
                                      userdata: pointer) {.
    importc: "gnutls_pkcs11_set_token_function", gnutls_import.}
proc gnutls_pkcs11_set_pin_function*(fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_pkcs11_set_pin_function", gnutls_import.}
proc gnutls_pkcs11_get_pin_function*(userdata: ptr pointer): gnutls_pin_callback_t {.
    importc: "gnutls_pkcs11_get_pin_function", gnutls_import.}
proc gnutls_pkcs11_add_provider*(name: cstring; params: cstring): cint {.
    importc: "gnutls_pkcs11_add_provider", gnutls_import.}
proc gnutls_pkcs11_obj_init*(obj: ptr gnutls_pkcs11_obj_t): cint {.
    importc: "gnutls_pkcs11_obj_init", gnutls_import.}
proc gnutls_pkcs11_obj_set_pin_function*(obj: gnutls_pkcs11_obj_t;
                                        fn: gnutls_pin_callback_t;
                                        userdata: pointer) {.
    importc: "gnutls_pkcs11_obj_set_pin_function", gnutls_import.}
## *
##  gnutls_pkcs11_obj_flags:
##  @GNUTLS_PKCS11_OBJ_FLAG_LOGIN: Force login in the token for the operation (seek+store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED: object marked as trusted (seek+store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE: object is explicitly marked as sensitive -unexportable (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO: force login as a security officer in the token for the operation (seek+store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE: marked as private -requires PIN to access (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_PRIVATE: marked as not private (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_ANY: When retrieving an object, do not set any requirements (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED: When retrieving an object, only retrieve the marked as trusted (alias to %GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED).
##    In gnutls_pkcs11_crt_is_known() it implies %GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_COMPARE if %GNUTLS_PKCS11_OBJ_FLAG_COMPARE_KEY is not given.
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_DISTRUSTED: When writing an object, mark it as distrusted (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED: When retrieving an object, only retrieve the marked as distrusted (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_COMPARE: When checking an object's presence, fully compare it before returning any result (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_COMPARE_KEY: When checking an object's presence, compare the key before returning any result (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE: The object must be present in a marked as trusted module (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_CA: Mark the object as a CA (seek+store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_KEY_WRAP: Mark the generated key pair as wrapping and unwrapping keys (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_OVERWRITE_TRUSTMOD_EXT: When an issuer is requested, override its extensions with the ones present in the trust module (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_ALWAYS_AUTH: Mark the key pair as requiring authentication (pin entry) before every operation (seek+store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_EXTRACTABLE: Mark the key pair as being extractable (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_NEVER_EXTRACTABLE: If set, the object was never marked as extractable (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_CRT: When searching, restrict to certificates only (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_PUBKEY: When searching, restrict to public key objects only (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY: When searching, restrict to private key objects only (seek).
##  @GNUTLS_PKCS11_OBJ_FLAG_NO_STORE_PUBKEY: When generating a keypair don't store the public key (store).
##  @GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_SENSITIVE: object marked as not sensitive -exportable (store).
##
##  Enumeration of different PKCS #11 object flags. Some flags are used
##  to mark objects when storing, while others are also used while seeking
##  or retrieving objects.
##

type
  gnutls_pkcs11_obj_flags* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS11_OBJ_FLAG_LOGIN = (1 shl 0),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED = (1 shl 1),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE = (1 shl 2),
    GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO = (1 shl 3),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE = (1 shl 4),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_PRIVATE = (1 shl 5),
    GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_ANY = (1 shl 6),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_DISTRUSTED = (1 shl 8),
    GNUTLS_PKCS11_OBJ_FLAG_COMPARE = (1 shl 9),
    GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE = (1 shl 10),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_CA = (1 shl 11),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_KEY_WRAP = (1 shl 12),
    GNUTLS_PKCS11_OBJ_FLAG_COMPARE_KEY = (1 shl 13),
    GNUTLS_PKCS11_OBJ_FLAG_OVERWRITE_TRUSTMOD_EXT = (1 shl 14),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_ALWAYS_AUTH = (1 shl 15),
    GNUTLS_PKCS11_OBJ_FLAG_MARK_EXTRACTABLE = (1 shl 16),
    GNUTLS_PKCS11_OBJ_FLAG_NEVER_EXTRACTABLE = (1 shl 17),
    GNUTLS_PKCS11_OBJ_FLAG_CRT = (1 shl 18),
    GNUTLS_PKCS11_OBJ_FLAG_WITH_PRIVKEY = (1 shl 19),
    GNUTLS_PKCS11_OBJ_FLAG_PUBKEY = (1 shl 20),
    GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY = (1 shl 21), GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_SENSITIVE = (
        1 shl 22)               ##  flags 1<<29 and later are reserved - see pkcs11_int.h

const
  GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED = GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED
  GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED = GNUTLS_PKCS11_OBJ_FLAG_MARK_DISTRUSTED
  GNUTLS_PKCS11_OBJ_FLAG_NO_STORE_PUBKEY = GNUTLS_PKCS11_OBJ_FLAG_PUBKEY

#const gnutls_pkcs11_obj_attr_t* = gnutls_pkcs11_obj_flags

## *
##  gnutls_pkcs11_url_type_t:
##  @GNUTLS_PKCS11_URL_GENERIC: A generic-purpose URL.
##  @GNUTLS_PKCS11_URL_LIB: A URL that specifies the library used as well.
##  @GNUTLS_PKCS11_URL_LIB_VERSION: A URL that specifies the library and its version.
##
##  Enumeration of different URL extraction flags.
##

type
  gnutls_pkcs11_url_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS11_URL_GENERIC, ##  URL specifies the object on token level
    GNUTLS_PKCS11_URL_LIB,    ##  URL specifies the object on module level
    GNUTLS_PKCS11_URL_LIB_VERSION ##  URL specifies the object on module and version level


proc gnutls_pkcs11_obj_import_url*(obj: gnutls_pkcs11_obj_t; url: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_import_url", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_pkcs11_obj_export_url*(obj: gnutls_pkcs11_obj_t;
                                  detailed: gnutls_pkcs11_url_type_t;
                                  url: cstringArray): cint {.
    importc: "gnutls_pkcs11_obj_export_url", gnutls_import.}
proc gnutls_pkcs11_obj_deinit*(obj: gnutls_pkcs11_obj_t) {.
    importc: "gnutls_pkcs11_obj_deinit", gnutls_import.}
proc gnutls_pkcs11_obj_export*(obj: gnutls_pkcs11_obj_t; output_data: pointer;
                              output_data_size: ptr csize): cint {.
    importc: "gnutls_pkcs11_obj_export", gnutls_import.}
proc gnutls_pkcs11_obj_export2*(obj: gnutls_pkcs11_obj_t; `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs11_obj_export2", gnutls_import.}
proc gnutls_pkcs11_obj_export3*(obj: gnutls_pkcs11_obj_t;
                               fmt: gnutls_x509_crt_fmt_t;
                               `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs11_obj_export3", gnutls_import.}
proc gnutls_pkcs11_get_raw_issuer*(url: cstring; cert: gnutls_x509_crt_t;
                                  issuer: ptr gnutls_datum_t;
                                  fmt: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pkcs11_get_raw_issuer", gnutls_import.}
proc gnutls_pkcs11_get_raw_issuer_by_dn*(url: cstring; dn: ptr gnutls_datum_t;
                                        issuer: ptr gnutls_datum_t;
                                        fmt: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pkcs11_get_raw_issuer_by_dn", gnutls_import.}
proc gnutls_pkcs11_get_raw_issuer_by_subject_key_id*(url: cstring;
    dn: ptr gnutls_datum_t; spki: ptr gnutls_datum_t; issuer: ptr gnutls_datum_t;
    fmt: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pkcs11_get_raw_issuer_by_subject_key_id", gnutls_import.}
proc gnutls_pkcs11_crt_is_known*(url: cstring; cert: gnutls_x509_crt_t; flags: cuint): cuint {.
    importc: "gnutls_pkcs11_crt_is_known", gnutls_import.}
#when 0:
#  ##  for documentation
#  proc gnutls_pkcs11_copy_x509_crt*(token_url: cstring; crt: gnutls_x509_crt_t;
#                                   label: cstring; flags: cuint): cint {.
#      importc: "gnutls_pkcs11_copy_x509_crt", gnutls_import.}
#    ##  GNUTLS_PKCS11_OBJ_FLAG_*
#  proc gnutls_pkcs11_copy_x509_privkey*(token_url: cstring;
#                                       key: gnutls_x509_privkey_t; label: cstring;
#                                       key_usage: cuint; flags: cuint): cint {.
#      importc: "gnutls_pkcs11_copy_x509_privkey", gnutls_import.}
#  proc gnutls_pkcs11_privkey_generate2*(url: cstring; pk: gnutls_pk_algorithm_t;
#                                       bits: cuint; label: cstring;
#                                       fmt: gnutls_x509_crt_fmt_t;
#                                       pubkey: ptr gnutls_datum_t; flags: cuint): cint {.
#      importc: "gnutls_pkcs11_privkey_generate2", gnutls_import.}
#  proc gnutls_pkcs11_privkey_generate*(url: cstring; pk: gnutls_pk_algorithm_t;
#                                      bits: cuint; label: cstring; flags: cuint): cint {.
#      importc: "gnutls_pkcs11_privkey_generate", gnutls_import.}
proc gnutls_pkcs11_copy_pubkey*(token_url: cstring; crt: gnutls_pubkey_t;
                               label: cstring; cid: ptr gnutls_datum_t;
                               key_usage: cuint; flags: cuint): cint {.
    importc: "gnutls_pkcs11_copy_pubkey", gnutls_import.}
template gnutls_pkcs11_copy_x509_crt*(url, crt, label, flags: untyped): untyped =
  gnutls_pkcs11_copy_x509_crt2(url, crt, label, nil, flags)

proc gnutls_pkcs11_copy_x509_crt2*(token_url: cstring; crt: gnutls_x509_crt_t;
                                  label: cstring; id: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs11_copy_x509_crt2", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
template gnutls_pkcs11_copy_x509_privkey*(url, key, label, usage, flags: untyped): untyped =
  gnutls_pkcs11_copy_x509_privkey2(url, key, label, nil, usage, flags)

proc gnutls_pkcs11_copy_x509_privkey2*(token_url: cstring;
                                      key: gnutls_x509_privkey_t; label: cstring;
                                      cid: ptr gnutls_datum_t; key_usage: cuint; ## GNUTLS_KEY_*
                                      flags: cuint): cint {.
    importc: "gnutls_pkcs11_copy_x509_privkey2", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_pkcs11_delete_url*(object_url: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_delete_url", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_pkcs11_copy_secret_key*(token_url: cstring; key: ptr gnutls_datum_t;
                                   label: cstring; key_usage: cuint; ##  GNUTLS_KEY_*
                                   flags: cuint): cint {.
    importc: "gnutls_pkcs11_copy_secret_key", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
## *
##  gnutls_pkcs11_obj_info_t:
##  @GNUTLS_PKCS11_OBJ_ID_HEX: The object ID in hex. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_LABEL: The object label. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_TOKEN_LABEL: The token's label. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_TOKEN_SERIAL: The token's serial number. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER: The token's manufacturer. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_TOKEN_MODEL: The token's model. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_ID: The object ID. Raw bytes.
##  @GNUTLS_PKCS11_OBJ_LIBRARY_VERSION: The library's version. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_LIBRARY_DESCRIPTION: The library's description. Null-terminated text.
##  @GNUTLS_PKCS11_OBJ_LIBRARY_MANUFACTURER: The library's manufacturer name. Null-terminated text.
##
##  Enumeration of several object information types.
##

type
  gnutls_pkcs11_obj_info_t* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS11_OBJ_ID_HEX = 1, GNUTLS_PKCS11_OBJ_LABEL,
    GNUTLS_PKCS11_OBJ_TOKEN_LABEL, GNUTLS_PKCS11_OBJ_TOKEN_SERIAL,
    GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER, GNUTLS_PKCS11_OBJ_TOKEN_MODEL, GNUTLS_PKCS11_OBJ_ID, ##  the pkcs11 provider library info
    GNUTLS_PKCS11_OBJ_LIBRARY_VERSION, GNUTLS_PKCS11_OBJ_LIBRARY_DESCRIPTION,
    GNUTLS_PKCS11_OBJ_LIBRARY_MANUFACTURER


proc gnutls_pkcs11_obj_get_ptr*(obj: gnutls_pkcs11_obj_t; `ptr`: ptr pointer;
                               session: ptr pointer; ohandle: ptr pointer;
                               slot_id: ptr culong; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_get_ptr", gnutls_import.}
proc gnutls_pkcs11_obj_get_info*(obj: gnutls_pkcs11_obj_t;
                                itype: gnutls_pkcs11_obj_info_t; output: pointer;
                                output_size: ptr csize): cint {.
    importc: "gnutls_pkcs11_obj_get_info", gnutls_import.}
proc gnutls_pkcs11_obj_set_info*(obj: gnutls_pkcs11_obj_t;
                                itype: gnutls_pkcs11_obj_info_t; data: pointer;
                                data_size: csize; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_set_info", gnutls_import.}
const
  GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL* = GNUTLS_PKCS11_OBJ_FLAG_CRT
  GNUTLS_PKCS11_OBJ_ATTR_MATCH* = 0
  GNUTLS_PKCS11_OBJ_ATTR_ALL* = 0
  GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED* = (
    GNUTLS_PKCS11_OBJ_FLAG_CRT or GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED)
  GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY* = (
    GNUTLS_PKCS11_OBJ_FLAG_CRT or GNUTLS_PKCS11_OBJ_FLAG_WITH_PRIVKEY)
  GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED_CA* = (GNUTLS_PKCS11_OBJ_FLAG_CRT or
      GNUTLS_PKCS11_OBJ_FLAG_MARK_CA or GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED)
  GNUTLS_PKCS11_OBJ_ATTR_PUBKEY* = GNUTLS_PKCS11_OBJ_FLAG_PUBKEY
  GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY* = GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY

## *
##  gnutls_pkcs11_token_info_t:
##  @GNUTLS_PKCS11_TOKEN_LABEL: The token's label (string)
##  @GNUTLS_PKCS11_TOKEN_SERIAL: The token's serial number (string)
##  @GNUTLS_PKCS11_TOKEN_MANUFACTURER: The token's manufacturer (string)
##  @GNUTLS_PKCS11_TOKEN_MODEL: The token's model (string)
##  @GNUTLS_PKCS11_TOKEN_MODNAME: The token's module name (string - since 3.4.3)
##
##  Enumeration of types for retrieving token information.
##

type
  gnutls_pkcs11_token_info_t* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS11_TOKEN_LABEL, GNUTLS_PKCS11_TOKEN_SERIAL,
    GNUTLS_PKCS11_TOKEN_MANUFACTURER, GNUTLS_PKCS11_TOKEN_MODEL,
    GNUTLS_PKCS11_TOKEN_MODNAME


## *
##  gnutls_pkcs11_obj_type_t:
##  @GNUTLS_PKCS11_OBJ_UNKNOWN: Unknown PKCS11 object.
##  @GNUTLS_PKCS11_OBJ_X509_CRT: X.509 certificate.
##  @GNUTLS_PKCS11_OBJ_PUBKEY: Public key.
##  @GNUTLS_PKCS11_OBJ_PRIVKEY: Private key.
##  @GNUTLS_PKCS11_OBJ_SECRET_KEY: Secret key.
##  @GNUTLS_PKCS11_OBJ_DATA: Data object.
##  @GNUTLS_PKCS11_OBJ_X509_CRT_EXTENSION: X.509 certificate extension (supported by p11-kit trust module only).
##
##  Enumeration of object types.
##

type
  gnutls_pkcs11_obj_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS11_OBJ_UNKNOWN, GNUTLS_PKCS11_OBJ_X509_CRT,
    GNUTLS_PKCS11_OBJ_PUBKEY, GNUTLS_PKCS11_OBJ_PRIVKEY,
    GNUTLS_PKCS11_OBJ_SECRET_KEY, GNUTLS_PKCS11_OBJ_DATA,
    GNUTLS_PKCS11_OBJ_X509_CRT_EXTENSION


proc gnutls_pkcs11_token_init*(token_url: cstring; so_pin: cstring; label: cstring): cint {.
    importc: "gnutls_pkcs11_token_init", gnutls_import.}
proc gnutls_pkcs11_token_get_ptr*(url: cstring; `ptr`: ptr pointer;
                                 slot_id: ptr culong; flags: cuint): cint {.
    importc: "gnutls_pkcs11_token_get_ptr", gnutls_import.}
proc gnutls_pkcs11_token_get_mechanism*(url: cstring; idx: cuint;
                                       mechanism: ptr culong): cint {.
    importc: "gnutls_pkcs11_token_get_mechanism", gnutls_import.}
proc gnutls_pkcs11_token_check_mechanism*(url: cstring; mechanism: culong;
    `ptr`: pointer; psize: cuint; flags: cuint): cuint {.
    importc: "gnutls_pkcs11_token_check_mechanism", gnutls_import.}
proc gnutls_pkcs11_token_set_pin*(token_url: cstring; oldpin: cstring;
                                 newpin: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_token_set_pin", gnutls_import.}
  ## gnutls_pin_flag_t
proc gnutls_pkcs11_token_get_url*(seq: cuint; detailed: gnutls_pkcs11_url_type_t;
                                 url: cstringArray): cint {.
    importc: "gnutls_pkcs11_token_get_url", gnutls_import.}
proc gnutls_pkcs11_token_get_info*(url: cstring; ttype: gnutls_pkcs11_token_info_t;
                                  output: pointer; output_size: ptr csize): cint {.
    importc: "gnutls_pkcs11_token_get_info", gnutls_import.}
const
  GNUTLS_PKCS11_TOKEN_HW* = 1
  GNUTLS_PKCS11_TOKEN_TRUSTED* = (1 shl 1) ##  p11-kit trusted
  GNUTLS_PKCS11_TOKEN_RNG* = (1 shl 2) ##  CKF_RNG
  GNUTLS_PKCS11_TOKEN_LOGIN_REQUIRED* = (1 shl 3) ##  CKF_LOGIN_REQUIRED
  GNUTLS_PKCS11_TOKEN_PROTECTED_AUTHENTICATION_PATH* = (1 shl 4) ##  CKF_PROTECTED_AUTHENTICATION_PATH
  GNUTLS_PKCS11_TOKEN_INITIALIZED* = (1 shl 5) ##  CKF_TOKEN_INITIALIZED
  GNUTLS_PKCS11_TOKEN_USER_PIN_COUNT_LOW* = (1 shl 6) ##  CKF_USER_PIN_COUNT_LOW
  GNUTLS_PKCS11_TOKEN_USER_PIN_FINAL_TRY* = (1 shl 7) ##  CKF_USER_PIN_FINAL_TRY
  GNUTLS_PKCS11_TOKEN_USER_PIN_LOCKED* = (1 shl 8) ##  CKF_USER_PIN_LOCKED
  GNUTLS_PKCS11_TOKEN_SO_PIN_COUNT_LOW* = (1 shl 9) ##  CKF_SO_PIN_COUNT_LOW
  GNUTLS_PKCS11_TOKEN_SO_PIN_FINAL_TRY* = (1 shl 10) ##  CKF_SO_PIN_FINAL_TRY
  GNUTLS_PKCS11_TOKEN_SO_PIN_LOCKED* = (1 shl 11) ##  CKF_SO_PIN_LOCKED
  GNUTLS_PKCS11_TOKEN_USER_PIN_INITIALIZED* = (1 shl 12) ##  CKF_USER_PIN_INITIALIZED
  GNUTLS_PKCS11_TOKEN_ERROR_STATE* = (1 shl 13) ##  CKF_ERROR_STATE

proc gnutls_pkcs11_token_get_flags*(url: cstring; flags: ptr cuint): cint {.
    importc: "gnutls_pkcs11_token_get_flags", gnutls_import.}
template gnutls_pkcs11_obj_list_import_url*(
    p_list, n_list, url, attrs, flags: untyped): untyped =
  gnutls_pkcs11_obj_list_import_url3(p_list, n_list, url, attrs or flags)

template gnutls_pkcs11_obj_list_import_url2*(
    p_list, n_list, url, attrs, flags: untyped): untyped =
  gnutls_pkcs11_obj_list_import_url4(p_list, n_list, url, attrs or flags)

proc gnutls_pkcs11_obj_list_import_url3*(p_list: ptr gnutls_pkcs11_obj_t;
                                        n_list: ptr cuint; url: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_list_import_url3", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_pkcs11_obj_list_import_url4*(p_list: ptr ptr gnutls_pkcs11_obj_t;
                                        n_list: ptr cuint; url: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_list_import_url4", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_x509_crt_import_pkcs11*(crt: gnutls_x509_crt_t;
                                   pkcs11_crt: gnutls_pkcs11_obj_t): cint {.
    importc: "gnutls_x509_crt_import_pkcs11", gnutls_import.}
proc gnutls_pkcs11_obj_get_type*(obj: gnutls_pkcs11_obj_t): gnutls_pkcs11_obj_type_t {.
    importc: "gnutls_pkcs11_obj_get_type", gnutls_import.}
proc gnutls_pkcs11_type_get_name*(`type`: gnutls_pkcs11_obj_type_t): cstring {.
    importc: "gnutls_pkcs11_type_get_name", gnutls_import.}
proc gnutls_pkcs11_obj_get_exts*(obj: gnutls_pkcs11_obj_t;
                                exts: ptr ptr gnutls_x509_ext_st;
                                exts_size: ptr cuint; flags: cuint): cint {.
    importc: "gnutls_pkcs11_obj_get_exts", gnutls_import.}
proc gnutls_pkcs11_obj_get_flags*(obj: gnutls_pkcs11_obj_t; oflags: ptr cuint): cint {.
    importc: "gnutls_pkcs11_obj_get_flags", gnutls_import.}
proc gnutls_pkcs11_obj_flags_get_str*(flags: cuint): cstring {.
    importc: "gnutls_pkcs11_obj_flags_get_str", gnutls_import.}
proc gnutls_x509_crt_list_import_pkcs11*(certs: ptr gnutls_x509_crt_t;
                                        cert_max: cuint;
                                        objs: ptr gnutls_pkcs11_obj_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_list_import_pkcs11", gnutls_import.}
  ##  must be zero
##  private key functions...

proc gnutls_pkcs11_privkey_init*(key: ptr gnutls_pkcs11_privkey_t): cint {.
    importc: "gnutls_pkcs11_privkey_init", gnutls_import.}
proc gnutls_pkcs11_privkey_cpy*(dst: gnutls_pkcs11_privkey_t;
                               src: gnutls_pkcs11_privkey_t): cint {.
    importc: "gnutls_pkcs11_privkey_cpy", gnutls_import.}
proc gnutls_pkcs11_privkey_set_pin_function*(key: gnutls_pkcs11_privkey_t;
    fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_pkcs11_privkey_set_pin_function", gnutls_import.}
proc gnutls_pkcs11_privkey_deinit*(key: gnutls_pkcs11_privkey_t) {.
    importc: "gnutls_pkcs11_privkey_deinit", gnutls_import.}
proc gnutls_pkcs11_privkey_get_pk_algorithm*(key: gnutls_pkcs11_privkey_t;
    bits: ptr cuint): cint {.importc: "gnutls_pkcs11_privkey_get_pk_algorithm",
                         gnutls_import.}
proc gnutls_pkcs11_privkey_get_info*(pkey: gnutls_pkcs11_privkey_t;
                                    itype: gnutls_pkcs11_obj_info_t;
                                    output: pointer; output_size: ptr csize): cint {.
    importc: "gnutls_pkcs11_privkey_get_info", gnutls_import.}
proc gnutls_pkcs11_privkey_import_url*(pkey: gnutls_pkcs11_privkey_t; url: cstring;
                                      flags: cuint): cint {.
    importc: "gnutls_pkcs11_privkey_import_url", gnutls_import.}
proc gnutls_pkcs11_privkey_export_url*(key: gnutls_pkcs11_privkey_t;
                                      detailed: gnutls_pkcs11_url_type_t;
                                      url: cstringArray): cint {.
    importc: "gnutls_pkcs11_privkey_export_url", gnutls_import.}
proc gnutls_pkcs11_privkey_status*(key: gnutls_pkcs11_privkey_t): cuint {.
    importc: "gnutls_pkcs11_privkey_status", gnutls_import.}
template gnutls_pkcs11_privkey_generate*(url, pk, bits, label, flags: untyped): untyped =
  gnutls_pkcs11_privkey_generate3(url, pk, bits, label, nil, 0, nil, 0, flags)

template gnutls_pkcs11_privkey_generate2*(
    url, pk, bits, label, fmt, pubkey, flags: untyped): untyped =
  gnutls_pkcs11_privkey_generate3(url, pk, bits, label, nil, fmt, pubkey, 0, flags)

proc gnutls_pkcs11_privkey_generate3*(url: cstring; pk: gnutls_pk_algorithm_t;
                                     bits: cuint; label: cstring;
                                     cid: ptr gnutls_datum_t;
                                     fmt: gnutls_x509_crt_fmt_t;
                                     pubkey: ptr gnutls_datum_t; key_usage: cuint;
                                     flags: cuint): cint {.
    importc: "gnutls_pkcs11_privkey_generate3", gnutls_import.}
proc gnutls_pkcs11_privkey_export_pubkey*(pkey: gnutls_pkcs11_privkey_t;
    fmt: gnutls_x509_crt_fmt_t; pubkey: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs11_privkey_export_pubkey", gnutls_import.}
proc gnutls_pkcs11_token_get_random*(token_url: cstring; data: pointer; len: csize): cint {.
    importc: "gnutls_pkcs11_token_get_random", gnutls_import.}
proc gnutls_pkcs11_copy_attached_extension*(token_url: cstring;
    crt: gnutls_x509_crt_t; data: ptr gnutls_datum_t; label: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs11_copy_attached_extension", gnutls_import.}
const
  gnutls_x509_crt_import_pkcs11_url* = gnutls_x509_crt_import_url

##  *INDENT-OFF*

##  *INDENT-ON*
