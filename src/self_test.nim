import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
##
##  Copyright (C) 2014 Free Software Foundation, Inc.
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

##  Self checking functions

const
  GNUTLS_SELF_TEST_FLAG_ALL* = 1
  GNUTLS_SELF_TEST_FLAG_NO_COMPAT* = (1 shl 1)

proc gnutls_cipher_self_test*(flags: cuint; cipher: gnutls_cipher_algorithm_t): cint {.
    importc: "gnutls_cipher_self_test", gnutls_import.}
proc gnutls_mac_self_test*(flags: cuint; mac: gnutls_mac_algorithm_t): cint {.
    importc: "gnutls_mac_self_test", gnutls_import.}
proc gnutls_digest_self_test*(flags: cuint; digest: gnutls_digest_algorithm_t): cint {.
    importc: "gnutls_digest_self_test", gnutls_import.}
proc gnutls_pk_self_test*(flags: cuint; pk: gnutls_pk_algorithm_t): cint {.
    importc: "gnutls_pk_self_test", gnutls_import.}