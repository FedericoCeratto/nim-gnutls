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

##  *INDENT-OFF*

##  *INDENT-ON*
##  PKCS12 structures handling
##

type
  gnutls_pkcs12_int* {.bycopy.} = object

  gnutls_pkcs12_t* = ptr gnutls_pkcs12_int
  gnutls_pkcs12_bag_int* {.bycopy.} = object

  gnutls_pkcs12_bag_t* = ptr gnutls_pkcs12_bag_int

proc gnutls_pkcs12_init*(pkcs12: ptr gnutls_pkcs12_t): cint {.
    importc: "gnutls_pkcs12_init", gnutls_import.}
proc gnutls_pkcs12_deinit*(pkcs12: gnutls_pkcs12_t) {.
    importc: "gnutls_pkcs12_deinit", gnutls_import.}
proc gnutls_pkcs12_import*(pkcs12: gnutls_pkcs12_t; data: ptr gnutls_datum_t;
                          format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pkcs12_import", gnutls_import.}
proc gnutls_pkcs12_export*(pkcs12: gnutls_pkcs12_t; format: gnutls_x509_crt_fmt_t;
                          output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_pkcs12_export", gnutls_import.}
proc gnutls_pkcs12_export2*(pkcs12: gnutls_pkcs12_t; format: gnutls_x509_crt_fmt_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs12_export2", gnutls_import.}
proc gnutls_pkcs12_get_bag*(pkcs12: gnutls_pkcs12_t; indx: cint;
                           bag: gnutls_pkcs12_bag_t): cint {.
    importc: "gnutls_pkcs12_get_bag", gnutls_import.}
proc gnutls_pkcs12_set_bag*(pkcs12: gnutls_pkcs12_t; bag: gnutls_pkcs12_bag_t): cint {.
    importc: "gnutls_pkcs12_set_bag", gnutls_import.}
proc gnutls_pkcs12_generate_mac*(pkcs12: gnutls_pkcs12_t; pass: cstring): cint {.
    importc: "gnutls_pkcs12_generate_mac", gnutls_import.}
proc gnutls_pkcs12_generate_mac2*(pkcs12: gnutls_pkcs12_t;
                                 mac: gnutls_mac_algorithm_t; pass: cstring): cint {.
    importc: "gnutls_pkcs12_generate_mac2", gnutls_import.}
proc gnutls_pkcs12_verify_mac*(pkcs12: gnutls_pkcs12_t; pass: cstring): cint {.
    importc: "gnutls_pkcs12_verify_mac", gnutls_import.}
proc gnutls_pkcs12_bag_decrypt*(bag: gnutls_pkcs12_bag_t; pass: cstring): cint {.
    importc: "gnutls_pkcs12_bag_decrypt", gnutls_import.}
proc gnutls_pkcs12_bag_encrypt*(bag: gnutls_pkcs12_bag_t; pass: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs12_bag_encrypt", gnutls_import.}
proc gnutls_pkcs12_bag_enc_info*(bag: gnutls_pkcs12_bag_t; schema: ptr cuint;
                                cipher: ptr cuint; salt: pointer;
                                salt_size: ptr cuint; iter_count: ptr cuint;
                                oid: cstringArray): cint {.
    importc: "gnutls_pkcs12_bag_enc_info", gnutls_import.}
proc gnutls_pkcs12_mac_info*(pkcs12: gnutls_pkcs12_t; mac: ptr cuint; salt: pointer;
                            salt_size: ptr cuint; iter_count: ptr cuint;
                            oid: cstringArray): cint {.
    importc: "gnutls_pkcs12_mac_info", gnutls_import.}
const
  GNUTLS_PKCS12_SP_INCLUDE_SELF_SIGNED* = 1

proc gnutls_pkcs12_simple_parse*(p12: gnutls_pkcs12_t; password: cstring;
                                key: ptr gnutls_x509_privkey_t;
                                chain: ptr ptr gnutls_x509_crt_t;
                                chain_len: ptr cuint;
                                extra_certs: ptr ptr gnutls_x509_crt_t;
                                extra_certs_len: ptr cuint;
                                crl: ptr gnutls_x509_crl_t; flags: cuint): cint {.
    importc: "gnutls_pkcs12_simple_parse", gnutls_import.}
## *
##  gnutls_pkcs12_bag_type_t:
##  @GNUTLS_BAG_EMPTY: Empty PKCS-12 bag.
##  @GNUTLS_BAG_PKCS8_ENCRYPTED_KEY: PKCS-12 bag with PKCS-8 encrypted key.
##  @GNUTLS_BAG_PKCS8_KEY: PKCS-12 bag with PKCS-8 key.
##  @GNUTLS_BAG_CERTIFICATE: PKCS-12 bag with certificate.
##  @GNUTLS_BAG_CRL: PKCS-12 bag with CRL.
##  @GNUTLS_BAG_SECRET: PKCS-12 bag with secret PKCS-9 keys.
##  @GNUTLS_BAG_ENCRYPTED: Encrypted PKCS-12 bag.
##  @GNUTLS_BAG_UNKNOWN: Unknown PKCS-12 bag.
##
##  Enumeration of different PKCS 12 bag types.
##

type
  gnutls_pkcs12_bag_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_BAG_EMPTY = 0, GNUTLS_BAG_PKCS8_ENCRYPTED_KEY = 1,
    GNUTLS_BAG_PKCS8_KEY = 2, GNUTLS_BAG_CERTIFICATE = 3, GNUTLS_BAG_CRL = 4, GNUTLS_BAG_SECRET = 5, ##  Secret data. Underspecified in pkcs-12,
                                                                                         ##  gnutls extension. We use the PKCS-9
                                                                                         ##  random nonce ID 1.2.840.113549.1.9.25.3
                                                                                         ##  to store randomly generated keys.
                                                                                         ##
    GNUTLS_BAG_ENCRYPTED = 10, GNUTLS_BAG_UNKNOWN = 20


proc gnutls_pkcs12_bag_get_type*(bag: gnutls_pkcs12_bag_t; indx: cuint): cint {.
    importc: "gnutls_pkcs12_bag_get_type", gnutls_import.}
proc gnutls_pkcs12_bag_get_data*(bag: gnutls_pkcs12_bag_t; indx: cuint;
                                data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs12_bag_get_data", gnutls_import.}
proc gnutls_pkcs12_bag_set_data*(bag: gnutls_pkcs12_bag_t;
                                `type`: gnutls_pkcs12_bag_type_t;
                                data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs12_bag_set_data", gnutls_import.}
proc gnutls_pkcs12_bag_set_crl*(bag: gnutls_pkcs12_bag_t; crl: gnutls_x509_crl_t): cint {.
    importc: "gnutls_pkcs12_bag_set_crl", gnutls_import.}
proc gnutls_pkcs12_bag_set_crt*(bag: gnutls_pkcs12_bag_t; crt: gnutls_x509_crt_t): cint {.
    importc: "gnutls_pkcs12_bag_set_crt", gnutls_import.}
proc gnutls_pkcs12_bag_set_privkey*(bag: gnutls_pkcs12_bag_t;
                                   privkey: gnutls_x509_privkey_t;
                                   password: cstring; flags: cuint): cint {.
    importc: "gnutls_pkcs12_bag_set_privkey", gnutls_import.}
proc gnutls_pkcs12_bag_init*(bag: ptr gnutls_pkcs12_bag_t): cint {.
    importc: "gnutls_pkcs12_bag_init", gnutls_import.}
proc gnutls_pkcs12_bag_deinit*(bag: gnutls_pkcs12_bag_t) {.
    importc: "gnutls_pkcs12_bag_deinit", gnutls_import.}
proc gnutls_pkcs12_bag_get_count*(bag: gnutls_pkcs12_bag_t): cint {.
    importc: "gnutls_pkcs12_bag_get_count", gnutls_import.}
proc gnutls_pkcs12_bag_get_key_id*(bag: gnutls_pkcs12_bag_t; indx: cuint;
                                  id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs12_bag_get_key_id", gnutls_import.}
proc gnutls_pkcs12_bag_set_key_id*(bag: gnutls_pkcs12_bag_t; indx: cuint;
                                  id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pkcs12_bag_set_key_id", gnutls_import.}
proc gnutls_pkcs12_bag_get_friendly_name*(bag: gnutls_pkcs12_bag_t; indx: cuint;
    name: cstringArray): cint {.importc: "gnutls_pkcs12_bag_get_friendly_name",
                             gnutls_import.}
proc gnutls_pkcs12_bag_set_friendly_name*(bag: gnutls_pkcs12_bag_t; indx: cuint;
    name: cstring): cint {.importc: "gnutls_pkcs12_bag_set_friendly_name",
                        gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
