import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
import x509
##
##  Copyright (C) 2003-2012 Free Software Foundation, Inc.
##  Copyright (C) 2015 Red Hat, Inc.
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
##  This file contains the types and prototypes for the X.509
##  certificate and CRL handling functions.
##

##  *INDENT-OFF*

##  *INDENT-ON*
##  PKCS7 structures handling
##

type
  gnutls_pkcs7_int* {.bycopy.} = object

  gnutls_pkcs7_t* = ptr gnutls_pkcs7_int

proc gnutls_pkcs7_init*(pkcs7: ptr gnutls_pkcs7_t): cint {.
    importc: "gnutls_pkcs7_init", gnutls_import.}
proc gnutls_pkcs7_deinit*(pkcs7: gnutls_pkcs7_t) {.importc: "gnutls_pkcs7_deinit",
    gnutls_import.}
proc gnutls_pkcs7_import*(pkcs7: gnutls_pkcs7_t; data: ptr gnutls_datum_t;
                         format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_pkcs7_import", gnutls_import.}
proc gnutls_pkcs7_export*(pkcs7: gnutls_pkcs7_t; format: gnutls_x509_crt_fmt_t;
                         output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_pkcs7_export", gnutls_import.}
proc gnutls_pkcs7_export2*(pkcs7: gnutls_pkcs7_t; format: gnutls_x509_crt_fmt_t;
                          `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_export2", gnutls_import.}
proc gnutls_pkcs7_get_signature_count*(pkcs7: gnutls_pkcs7_t): cint {.
    importc: "gnutls_pkcs7_get_signature_count", gnutls_import.}
const
  GNUTLS_PKCS7_EDATA_GET_RAW* = (1 shl 24)

proc gnutls_pkcs7_get_embedded_data*(pkcs7: gnutls_pkcs7_t; flags: cuint;
                                    data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_get_embedded_data", gnutls_import.}
proc gnutls_pkcs7_get_embedded_data_oid*(pkcs7: gnutls_pkcs7_t): cstring {.
    importc: "gnutls_pkcs7_get_embedded_data_oid", gnutls_import.}
proc gnutls_pkcs7_get_crt_count*(pkcs7: gnutls_pkcs7_t): cint {.
    importc: "gnutls_pkcs7_get_crt_count", gnutls_import.}
proc gnutls_pkcs7_get_crt_raw*(pkcs7: gnutls_pkcs7_t; indx: cuint;
                              certificate: pointer; certificate_size: ptr csize): cint {.
    importc: "gnutls_pkcs7_get_crt_raw", gnutls_import.}
proc gnutls_pkcs7_set_crt_raw*(pkcs7: gnutls_pkcs7_t; crt: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_set_crt_raw", gnutls_import.}
proc gnutls_pkcs7_set_crt*(pkcs7: gnutls_pkcs7_t; crt: gnutls_x509_crt_t): cint {.
    importc: "gnutls_pkcs7_set_crt", gnutls_import.}
proc gnutls_pkcs7_delete_crt*(pkcs7: gnutls_pkcs7_t; indx: cint): cint {.
    importc: "gnutls_pkcs7_delete_crt", gnutls_import.}
proc gnutls_pkcs7_get_crl_raw*(pkcs7: gnutls_pkcs7_t; indx: cuint; crl: pointer;
                              crl_size: ptr csize): cint {.
    importc: "gnutls_pkcs7_get_crl_raw", gnutls_import.}
proc gnutls_pkcs7_get_crl_count*(pkcs7: gnutls_pkcs7_t): cint {.
    importc: "gnutls_pkcs7_get_crl_count", gnutls_import.}
proc gnutls_pkcs7_set_crl_raw*(pkcs7: gnutls_pkcs7_t; crl: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_set_crl_raw", gnutls_import.}
proc gnutls_pkcs7_set_crl*(pkcs7: gnutls_pkcs7_t; crl: gnutls_x509_crl_t): cint {.
    importc: "gnutls_pkcs7_set_crl", gnutls_import.}
proc gnutls_pkcs7_delete_crl*(pkcs7: gnutls_pkcs7_t; indx: cint): cint {.
    importc: "gnutls_pkcs7_delete_crl", gnutls_import.}
type
  gnutls_pkcs7_attrs_t* = ptr gnutls_pkcs7_attrs_st
  gnutls_pkcs7_signature_info_st* {.bycopy.} = object
    algo*: gnutls_sign_algorithm_t
    sig*: gnutls_datum_t
    issuer_dn*: gnutls_datum_t
    signer_serial*: gnutls_datum_t
    issuer_keyid*: gnutls_datum_t
    signing_time*: time_t
    signed_attrs*: gnutls_pkcs7_attrs_t
    unsigned_attrs*: gnutls_pkcs7_attrs_t
    pad*: array[64, char]


proc gnutls_pkcs7_signature_info_deinit*(info: ptr gnutls_pkcs7_signature_info_st) {.
    importc: "gnutls_pkcs7_signature_info_deinit", gnutls_import.}
proc gnutls_pkcs7_get_signature_info*(pkcs7: gnutls_pkcs7_t; idx: cuint;
                                     info: ptr gnutls_pkcs7_signature_info_st): cint {.
    importc: "gnutls_pkcs7_get_signature_info", gnutls_import.}
proc gnutls_pkcs7_verify_direct*(pkcs7: gnutls_pkcs7_t; signer: gnutls_x509_crt_t;
                                idx: cuint; data: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs7_verify_direct", gnutls_import.}
proc gnutls_pkcs7_verify*(pkcs7: gnutls_pkcs7_t; tl: gnutls_x509_trust_list_t;
                         vdata: ptr gnutls_typed_vdata_st; vdata_size: cuint;
                         idx: cuint; data: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs7_verify", gnutls_import.}
const
  GNUTLS_PKCS7_ATTR_ENCODE_OCTET_STRING* = 1

proc gnutls_pkcs7_add_attr*(list: ptr gnutls_pkcs7_attrs_t; oid: cstring;
                           data: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs7_add_attr", gnutls_import.}
proc gnutls_pkcs7_attrs_deinit*(list: gnutls_pkcs7_attrs_t) {.
    importc: "gnutls_pkcs7_attrs_deinit", gnutls_import.}
proc gnutls_pkcs7_get_attr*(list: gnutls_pkcs7_attrs_t; idx: cuint;
                           oid: cstringArray; data: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pkcs7_get_attr", gnutls_import.}
## *
##  gnutls_pkcs7_sign_flags:
##  @GNUTLS_PKCS7_EMBED_DATA: The signed data will be embedded in the structure.
##  @GNUTLS_PKCS7_INCLUDE_TIME: The signing time will be included in the structure.
##  @GNUTLS_PKCS7_INCLUDE_CERT: The signer's certificate will be included in the cert list.
##  @GNUTLS_PKCS7_WRITE_SPKI: Use the signer's key identifier instead of name.
##
##  Enumeration of the different PKCS #7 signature flags.
##

type
  gnutls_pkcs7_sign_flags* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS7_EMBED_DATA = 1, GNUTLS_PKCS7_INCLUDE_TIME = (1 shl 1),
    GNUTLS_PKCS7_INCLUDE_CERT = (1 shl 2), GNUTLS_PKCS7_WRITE_SPKI = (1 shl 3)


proc gnutls_pkcs7_sign*(pkcs7: gnutls_pkcs7_t; signer: gnutls_x509_crt_t;
                       signer_key: gnutls_privkey_t; data: ptr gnutls_datum_t;
                       signed_attrs: gnutls_pkcs7_attrs_t;
                       unsigned_attrs: gnutls_pkcs7_attrs_t;
                       dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_pkcs7_sign", gnutls_import.}
proc gnutls_pkcs7_get_crt_raw2*(pkcs7: gnutls_pkcs7_t; indx: cuint;
                               cert: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_get_crt_raw2", gnutls_import.}
proc gnutls_pkcs7_get_crl_raw2*(pkcs7: gnutls_pkcs7_t; indx: cuint;
                               crl: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_get_crl_raw2", gnutls_import.}
proc gnutls_pkcs7_print*(pkcs7: gnutls_pkcs7_t;
                        format: gnutls_certificate_print_formats_t;
                        `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs7_print", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
