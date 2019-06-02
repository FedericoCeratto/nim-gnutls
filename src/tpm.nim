import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2010-2012 Free Software Foundation, Inc.
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

type
  tpm_key_list_st* {.bycopy.} = object

  gnutls_tpm_key_list_t* = ptr tpm_key_list_st

const
  GNUTLS_TPM_KEY_SIGNING* = (1 shl 1)
  GNUTLS_TPM_REGISTER_KEY* = (1 shl 2)
  GNUTLS_TPM_KEY_USER* = (1 shl 3)

## *
##  gnutls_tpmkey_fmt_t:
##  @GNUTLS_TPMKEY_FMT_RAW: The portable data format.
##  @GNUTLS_TPMKEY_FMT_DER: An alias for the raw format.
##  @GNUTLS_TPMKEY_FMT_CTK_PEM: A custom data format used by some TPM tools.
##
##  Enumeration of different certificate encoding formats.
##

type
  gnutls_tpmkey_fmt_t* {.size: sizeof(cint).} = enum
    GNUTLS_TPMKEY_FMT_RAW = 0, GNUTLS_TPMKEY_FMT_CTK_PEM = 1

const
  GNUTLS_TPMKEY_FMT_DER = GNUTLS_TPMKEY_FMT_RAW

proc gnutls_tpm_privkey_generate*(pk: gnutls_pk_algorithm_t; bits: cuint;
                                 srk_password: cstring; key_password: cstring;
                                 format: gnutls_tpmkey_fmt_t;
                                 pub_format: gnutls_x509_crt_fmt_t;
                                 privkey: ptr gnutls_datum_t;
                                 pubkey: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_tpm_privkey_generate", gnutls_import.}
proc gnutls_tpm_key_list_deinit*(list: gnutls_tpm_key_list_t) {.
    importc: "gnutls_tpm_key_list_deinit", gnutls_import.}
proc gnutls_tpm_key_list_get_url*(list: gnutls_tpm_key_list_t; idx: cuint;
                                 url: cstringArray; flags: cuint): cint {.
    importc: "gnutls_tpm_key_list_get_url", gnutls_import.}
proc gnutls_tpm_get_registered*(list: ptr gnutls_tpm_key_list_t): cint {.
    importc: "gnutls_tpm_get_registered", gnutls_import.}
proc gnutls_tpm_privkey_delete*(url: cstring; srk_password: cstring): cint {.
    importc: "gnutls_tpm_privkey_delete", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
