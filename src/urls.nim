import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2014 Red Hat, Inc.
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

##  This API allows to register application specific URLs for
##  keys and certificates.
##
##  *INDENT-OFF*

##  *INDENT-ON*

type
  gnutls_privkey_import_url_func* = proc (pkey: gnutls_privkey_t; url: cstring;
                                       flags: cuint): cint
  gnutls_x509_crt_import_url_func* = proc (pkey: gnutls_x509_crt_t; url: cstring;
                                        flags: cuint): cint

##  The following callbacks are optional
##  This is to enable gnutls_pubkey_import_url()

type
  gnutls_pubkey_import_url_func* = proc (pkey: gnutls_pubkey_t; url: cstring;
                                      flags: cuint): cint

##  This is to allow constructing a certificate chain. It will be provided
##  the initial certificate URL and the certificate to find its issuer, and must
##  return zero and the DER encoding of the issuer's certificate. If not available,
##  it should return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.

type
  gnutls_get_raw_issuer_func* = proc (url: cstring; crt: gnutls_x509_crt_t;
                                   issuer_der: ptr gnutls_datum_t; flags: cuint): cint
  gnutls_custom_url_st* {.bycopy.} = object
    name*: cstring
    name_size*: cuint
    import_key*: gnutls_privkey_import_url_func
    import_crt*: gnutls_x509_crt_import_url_func
    import_pubkey*: gnutls_pubkey_import_url_func
    get_issuer*: gnutls_get_raw_issuer_func
    future1*: pointer          ##  replace in a future extension
    future2*: pointer          ##  replace in a future extension


proc gnutls_register_custom_url*(st: ptr gnutls_custom_url_st): cint {.
    importc: "gnutls_register_custom_url", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
