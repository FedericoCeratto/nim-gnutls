import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
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

##  This API allows to access user key and certificate pairs that are
##  available in the current system. If any passwords are required,
##  they will be requested through the pin callbacks.
##
##  *INDENT-OFF*

##  *INDENT-ON*

type
  system_key_iter_st* {.bycopy.} = object

  gnutls_system_key_iter_t* = ptr system_key_iter_st

proc gnutls_system_key_iter_deinit*(iter: gnutls_system_key_iter_t) {.
    importc: "gnutls_system_key_iter_deinit", gnutls_import.}
proc gnutls_system_key_iter_get_info*(iter: ptr gnutls_system_key_iter_t; cert_type: cuint; ##  gnutls_certificate_type_t
                                     cert_url: cstringArray;
                                     key_url: cstringArray; label: cstringArray;
                                     der: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_system_key_iter_get_info", gnutls_import.}
proc gnutls_system_key_delete*(cert_url: cstring; key_url: cstring): cint {.
    importc: "gnutls_system_key_delete", gnutls_import.}
proc gnutls_system_key_add_x509*(crt: gnutls_x509_crt_t;
                                privkey: gnutls_x509_privkey_t; label: cstring;
                                cert_url: cstringArray; key_url: cstringArray): cint {.
    importc: "gnutls_system_key_add_x509", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
