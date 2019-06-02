import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import x509
import gnutls
import pkcs11
import openpgp
from tpm import gnutls_tpmkey_fmt_t
##
##  Copyright (C) 2010-2012 Free Software Foundation, Inc.
##  Copyright (C) 2015-2017 Red Hat, Inc.
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
##  Public key operations

## *
##  gnutls_pubkey_flags:
##  @GNUTLS_PUBKEY_DISABLE_CALLBACKS: The following flag disables call to PIN callbacks. Only
##    relevant to TPM keys.
##  @GNUTLS_PUBKEY_GET_OPENPGP_FINGERPRINT: request an OPENPGP fingerprint instead of the default.
##
##  Enumeration of different certificate import flags.
##

type
  gnutls_pubkey_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_PUBKEY_DISABLE_CALLBACKS = 1 shl 2,
    GNUTLS_PUBKEY_GET_OPENPGP_FINGERPRINT = 1 shl 3


## *
##  gnutls_abstract_export_flags:
##  @GNUTLS_EXPORT_FLAG_NO_LZ: do not prepend a leading zero to exported values
##
##  Enumeration of different certificate import flags.
##

type
  gnutls_abstract_export_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_EXPORT_FLAG_NO_LZ = 1


const
  GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA* = GNUTLS_VERIFY_USE_TLS1_RSA
  GNUTLS_PUBKEY_VERIFY_FLAG_TLS_RSA* = GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA


type
  gnutls_privkey_sign_func* = proc (key: gnutls_privkey_t; userdata: pointer;
                                 raw_data: ptr gnutls_datum_t;
                                 signature: ptr gnutls_datum_t): cint
  gnutls_privkey_decrypt_func* = proc (key: gnutls_privkey_t; userdata: pointer;
                                    ciphertext: ptr gnutls_datum_t;
                                    plaintext: ptr gnutls_datum_t): cint
  gnutls_privkey_decrypt_func2* = proc (key: gnutls_privkey_t; userdata: pointer;
                                     ciphertext: ptr gnutls_datum_t;
                                     plaintext: ptr cuchar; plaintext_size: csize): cint

##  to be called to sign pre-hashed data. The input will be
##  the output of the hash (such as SHA256) corresponding to
##  the signature algorithm. The algorithm GNUTLS_SIGN_RSA_RAW
##  will be provided when RSA PKCS#1 DigestInfo structure is provided
##  as data (when this is called from a TLS 1.0 or 1.1 session).
##

type
  gnutls_privkey_sign_hash_func* = proc (key: gnutls_privkey_t;
                                      algo: gnutls_sign_algorithm_t;
                                      userdata: pointer; flags: cuint;
                                      hash: ptr gnutls_datum_t;
                                      signature: ptr gnutls_datum_t): cint

##  to be called to sign data. The input data will be
##  the data to be signed (and hashed), with the provided
##  signature algorithm. This function is used for algorithms
##  like ed25519 which cannot take pre-hashed data as input.
##

type
  gnutls_privkey_sign_data_func* = proc (key: gnutls_privkey_t;
                                      algo: gnutls_sign_algorithm_t;
                                      userdata: pointer; flags: cuint;
                                      data: ptr gnutls_datum_t;
                                      signature: ptr gnutls_datum_t): cint
  gnutls_privkey_deinit_func* = proc (key: gnutls_privkey_t; userdata: pointer)

template GNUTLS_SIGN_ALGO_TO_FLAGS*(sig: untyped): untyped =
  cast[cuint](((sig) shl 20))

template GNUTLS_FLAGS_TO_SIGN_ALGO*(flags: untyped): untyped =
  cast[cuint](((flags) shr 20))

##  Should return the public key algorithm (gnutls_pk_algorithm_t)

const
  GNUTLS_PRIVKEY_INFO_PK_ALGO* = 1

##  Should return the preferred signature algorithm (gnutls_sign_algorithm_t) or 0.

const
  GNUTLS_PRIVKEY_INFO_SIGN_ALGO* = (1 shl 1)

##  Should return true (1) or false (0) if the provided sign algorithm
##  (obtained with GNUTLS_FLAGS_TO_SIGN_ALGO) is supported.
##

const
  GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO* = (1 shl 2)

##  Should return the number of bits of the public key algorithm (required for RSA-PSS)
##  It is the value that should be returned by gnutls_pubkey_get_pk_algorithm()

const
  GNUTLS_PRIVKEY_INFO_PK_ALGO_BITS* = (1 shl 3)

##  returns information on the public key associated with userdata

type
  gnutls_privkey_info_func* = proc (key: gnutls_privkey_t; flags: cuint;
                                 userdata: pointer): cint

proc gnutls_pubkey_init*(key: ptr gnutls_pubkey_t): cint {.
    importc: "gnutls_pubkey_init", gnutls_import.}
proc gnutls_pubkey_deinit*(key: gnutls_pubkey_t) {.importc: "gnutls_pubkey_deinit",
    gnutls_import.}
proc gnutls_pubkey_verify_params*(key: gnutls_pubkey_t): cint {.
    importc: "gnutls_pubkey_verify_params", gnutls_import.}
proc gnutls_pubkey_set_pin_function*(key: gnutls_pubkey_t;
                                    fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_pubkey_set_pin_function", gnutls_import.}
proc gnutls_pubkey_get_pk_algorithm*(key: gnutls_pubkey_t; bits: ptr cuint): cint {.
    importc: "gnutls_pubkey_get_pk_algorithm", gnutls_import.}
proc gnutls_pubkey_set_spki*(key: gnutls_pubkey_t; spki: gnutls_x509_spki_t;
                            flags: cuint): cint {.
    importc: "gnutls_pubkey_set_spki", gnutls_import.}
proc gnutls_pubkey_get_spki*(key: gnutls_pubkey_t; spki: gnutls_x509_spki_t;
                            flags: cuint): cint {.
    importc: "gnutls_pubkey_get_spki", gnutls_import.}
proc gnutls_pubkey_import_x509*(key: gnutls_pubkey_t; crt: gnutls_x509_crt_t;
                               flags: cuint): cint {.
    importc: "gnutls_pubkey_import_x509", gnutls_import.}
proc gnutls_pubkey_import_x509_crq*(key: gnutls_pubkey_t; crq: gnutls_x509_crq_t;
                                   flags: cuint): cint {.
    importc: "gnutls_pubkey_import_x509_crq", gnutls_import.}
proc gnutls_pubkey_import_pkcs11*(key: gnutls_pubkey_t; obj: gnutls_pkcs11_obj_t;
                                 flags: cuint): cint {.
    importc: "gnutls_pubkey_import_pkcs11", gnutls_import.}
proc gnutls_pubkey_import_openpgp*(key: gnutls_pubkey_t; crt: gnutls_openpgp_crt_t;
                                  flags: cuint): cint {.
    importc: "gnutls_pubkey_import_openpgp", gnutls_import.}
proc gnutls_pubkey_import_openpgp_raw*(pkey: gnutls_pubkey_t;
                                      data: ptr gnutls_datum_t;
                                      format: gnutls_openpgp_crt_fmt_t;
                                      keyid: gnutls_openpgp_keyid_t; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_openpgp_raw", gnutls_import.}

proc gnutls_pubkey_import_x509_raw*(pkey: gnutls_pubkey_t;
                                   data: ptr gnutls_datum_t;
                                   format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_x509_raw", gnutls_import.}

proc gnutls_pubkey_import_privkey*(key: gnutls_pubkey_t; pkey: gnutls_privkey_t;
                                  usage: cuint; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_privkey", gnutls_import.}
proc gnutls_pubkey_import_tpm_url*(pkey: gnutls_pubkey_t; url: cstring;
                                  srk_password: cstring; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_tpm_url", gnutls_import.}
proc gnutls_pubkey_import_url*(key: gnutls_pubkey_t; url: cstring; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_url", gnutls_import.}
proc gnutls_pubkey_import_tpm_raw*(pkey: gnutls_pubkey_t;
                                  fdata: ptr gnutls_datum_t;
                                  format: gnutls_tpmkey_fmt_t;
                                  srk_password: cstring; flags: cuint): cint {.
    importc: "gnutls_pubkey_import_tpm_raw", gnutls_import.}
proc gnutls_pubkey_get_preferred_hash_algorithm*(key: gnutls_pubkey_t;
    hash: ptr gnutls_digest_algorithm_t; mand: ptr cuint): cint {.
    importc: "gnutls_pubkey_get_preferred_hash_algorithm", gnutls_import.}

proc gnutls_pubkey_export_rsa_raw*(key: gnutls_pubkey_t; m: ptr gnutls_datum_t;
                                  e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_export_rsa_raw", gnutls_import.}

const gnutls_pubkey_get_pk_rsa_raw* = gnutls_pubkey_export_rsa_raw

proc gnutls_pubkey_export_rsa_raw2*(key: gnutls_pubkey_t; m: ptr gnutls_datum_t;
                                   e: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pubkey_export_rsa_raw2", gnutls_import.}

proc gnutls_pubkey_export_dsa_raw*(key: gnutls_pubkey_t; p: ptr gnutls_datum_t;
                                  q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                  y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_export_dsa_raw", gnutls_import.}

const gnutls_pubkey_get_pk_dsa_raw* = gnutls_pubkey_export_dsa_raw

proc gnutls_pubkey_export_dsa_raw2*(key: gnutls_pubkey_t; p: ptr gnutls_datum_t;
                                   q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                   y: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_pubkey_export_dsa_raw2", gnutls_import.}
proc gnutls_pubkey_export_ecc_raw2*(key: gnutls_pubkey_t;
                                   curve: ptr gnutls_ecc_curve_t;
                                   x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                   flags: cuint): cint {.
    importc: "gnutls_pubkey_export_ecc_raw2", gnutls_import.}
proc gnutls_pubkey_export_gost_raw2*(key: gnutls_pubkey_t;
                                    curve: ptr gnutls_ecc_curve_t;
                                    digest: ptr gnutls_digest_algorithm_t;
                                    paramset: ptr gnutls_gost_paramset_t;
                                    x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                    flags: cuint): cint {.
    importc: "gnutls_pubkey_export_gost_raw2", gnutls_import.}
proc gnutls_pubkey_export_ecc_raw*(key: gnutls_pubkey_t;
                                  curve: ptr gnutls_ecc_curve_t;
                                  x: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_export_ecc_raw", gnutls_import.}
const gnutls_pubkey_get_pk_ecc_raw* = gnutls_pubkey_export_ecc_raw

proc gnutls_pubkey_export_ecc_x962*(key: gnutls_pubkey_t;
                                   parameters: ptr gnutls_datum_t;
                                   ecpoint: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_export_ecc_x962", gnutls_import.}
const gnutls_pubkey_get_pk_ecc_x962* = gnutls_pubkey_export_ecc_x962

proc gnutls_pubkey_export*(key: gnutls_pubkey_t; format: gnutls_x509_crt_fmt_t;
                          output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_pubkey_export", gnutls_import.}
proc gnutls_pubkey_export2*(key: gnutls_pubkey_t; format: gnutls_x509_crt_fmt_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_export2", gnutls_import.}
proc gnutls_pubkey_get_key_id*(key: gnutls_pubkey_t; flags: cuint;
                              output_data: ptr cuchar; output_data_size: ptr csize): cint {.
    importc: "gnutls_pubkey_get_key_id", gnutls_import.}
proc gnutls_pubkey_get_openpgp_key_id*(key: gnutls_pubkey_t; flags: cuint;
                                      output_data: ptr cuchar;
                                      output_data_size: ptr csize;
                                      subkey: ptr cuint): cint {.
    importc: "gnutls_pubkey_get_openpgp_key_id", gnutls_import.}
proc gnutls_pubkey_get_key_usage*(key: gnutls_pubkey_t; usage: ptr cuint): cint {.
    importc: "gnutls_pubkey_get_key_usage", gnutls_import.}
proc gnutls_pubkey_set_key_usage*(key: gnutls_pubkey_t; usage: cuint): cint {.
    importc: "gnutls_pubkey_set_key_usage", gnutls_import.}
proc gnutls_pubkey_import*(key: gnutls_pubkey_t; data: ptr gnutls_datum_t;
                          format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_pubkey_import", gnutls_import.}
template gnutls_pubkey_import_pkcs11_url*(key, url, flags: untyped): untyped =
  gnutls_pubkey_import_url(key, url, flags)

proc gnutls_pubkey_import_dsa_raw*(key: gnutls_pubkey_t; p: ptr gnutls_datum_t;
                                  q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                  y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_import_dsa_raw", gnutls_import.}
proc gnutls_pubkey_import_rsa_raw*(key: gnutls_pubkey_t; m: ptr gnutls_datum_t;
                                  e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_import_rsa_raw", gnutls_import.}
proc gnutls_pubkey_import_ecc_x962*(key: gnutls_pubkey_t;
                                   parameters: ptr gnutls_datum_t;
                                   ecpoint: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_import_ecc_x962", gnutls_import.}
proc gnutls_pubkey_import_ecc_raw*(key: gnutls_pubkey_t; curve: gnutls_ecc_curve_t;
                                  x: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_import_ecc_raw", gnutls_import.}
proc gnutls_pubkey_import_gost_raw*(key: gnutls_pubkey_t;
                                   curve: gnutls_ecc_curve_t;
                                   digest: gnutls_digest_algorithm_t;
                                   paramset: gnutls_gost_paramset_t;
                                   x: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_import_gost_raw", gnutls_import.}
proc gnutls_pubkey_encrypt_data*(key: gnutls_pubkey_t; flags: cuint;
                                plaintext: ptr gnutls_datum_t;
                                ciphertext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_encrypt_data", gnutls_import.}
proc gnutls_x509_crt_set_pubkey*(crt: gnutls_x509_crt_t; key: gnutls_pubkey_t): cint {.
    importc: "gnutls_x509_crt_set_pubkey", gnutls_import.}
proc gnutls_x509_crq_set_pubkey*(crq: gnutls_x509_crq_t; key: gnutls_pubkey_t): cint {.
    importc: "gnutls_x509_crq_set_pubkey", gnutls_import.}
proc gnutls_pubkey_verify_hash2*(key: gnutls_pubkey_t;
                                algo: gnutls_sign_algorithm_t; flags: cuint;
                                hash: ptr gnutls_datum_t;
                                signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_verify_hash2", gnutls_import.}
proc gnutls_pubkey_verify_data2*(pubkey: gnutls_pubkey_t;
                                algo: gnutls_sign_algorithm_t; flags: cuint;
                                data: ptr gnutls_datum_t;
                                signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_verify_data2", gnutls_import.}
##  Private key operations

proc gnutls_privkey_init*(key: ptr gnutls_privkey_t): cint {.
    importc: "gnutls_privkey_init", gnutls_import.}
proc gnutls_privkey_deinit*(key: gnutls_privkey_t) {.
    importc: "gnutls_privkey_deinit", gnutls_import.}
##  macros to allow specifying a subgroup and group size in gnutls_privkey_generate()
##  and gnutls_x509_privkey_generate()

template GNUTLS_SUBGROUP_TO_BITS*(group, subgroup: untyped): untyped =
  cast[cuint](((subgroup shl 16) or (group)))

template GNUTLS_BITS_TO_SUBGROUP*(bits: untyped): untyped =
  ((bits shr 16) and 0x0000FFFF)

template GNUTLS_BITS_TO_GROUP*(bits: untyped): untyped =
  (bits and 0x0000FFFF)

template GNUTLS_BITS_HAVE_SUBGROUP*(bits: untyped): untyped =
  ((bits) and 0xFFFF0000)

proc gnutls_privkey_generate*(key: gnutls_privkey_t; algo: gnutls_pk_algorithm_t;
                             bits: cuint; flags: cuint): cint {.
    importc: "gnutls_privkey_generate", gnutls_import.}
proc gnutls_privkey_generate2*(pkey: gnutls_privkey_t; algo: gnutls_pk_algorithm_t;
                              bits: cuint; flags: cuint;
                              data: ptr gnutls_keygen_data_st; data_size: cuint): cint {.
    importc: "gnutls_privkey_generate2", gnutls_import.}
proc gnutls_privkey_set_spki*(key: gnutls_privkey_t; spki: gnutls_x509_spki_t;
                             flags: cuint): cint {.
    importc: "gnutls_privkey_set_spki", gnutls_import.}
proc gnutls_privkey_get_spki*(key: gnutls_privkey_t; spki: gnutls_x509_spki_t;
                             flags: cuint): cint {.
    importc: "gnutls_privkey_get_spki", gnutls_import.}
proc gnutls_privkey_verify_seed*(key: gnutls_privkey_t;
                                a2: gnutls_digest_algorithm_t; seed: pointer;
                                seed_size: csize): cint {.
    importc: "gnutls_privkey_verify_seed", gnutls_import.}
proc gnutls_privkey_get_seed*(key: gnutls_privkey_t;
                             a2: ptr gnutls_digest_algorithm_t; seed: pointer;
                             seed_size: ptr csize): cint {.
    importc: "gnutls_privkey_get_seed", gnutls_import.}
proc gnutls_privkey_verify_params*(key: gnutls_privkey_t): cint {.
    importc: "gnutls_privkey_verify_params", gnutls_import.}
proc gnutls_privkey_set_flags*(key: gnutls_privkey_t; flags: cuint) {.
    importc: "gnutls_privkey_set_flags", gnutls_import.}
proc gnutls_privkey_set_pin_function*(key: gnutls_privkey_t;
                                     fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_privkey_set_pin_function", gnutls_import.}
proc gnutls_privkey_get_pk_algorithm*(key: gnutls_privkey_t; bits: ptr cuint): cint {.
    importc: "gnutls_privkey_get_pk_algorithm", gnutls_import.}
proc gnutls_privkey_get_type*(key: gnutls_privkey_t): gnutls_privkey_type_t {.
    importc: "gnutls_privkey_get_type", gnutls_import.}
proc gnutls_privkey_status*(key: gnutls_privkey_t): cint {.
    importc: "gnutls_privkey_status", gnutls_import.}
## *
##  gnutls_privkey_flags:
##  @GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA: Make an RSA signature on the hashed data as in the TLS protocol.
##  @GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS: Make an RSA signature on the hashed data with the PSS padding.
##  @GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE: Make an RSA-PSS signature on the hashed data with reproducible parameters (zero salt).
##  @GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE: When importing a private key, automatically
##    release it when the structure it was imported is released.
##  @GNUTLS_PRIVKEY_IMPORT_COPY: Copy required values during import.
##  @GNUTLS_PRIVKEY_DISABLE_CALLBACKS: The following flag disables call to PIN callbacks etc.
##    Only relevant to TPM keys.
##  @GNUTLS_PRIVKEY_FLAG_PROVABLE: When generating a key involving prime numbers, use provable primes; a seed may be required.
##  @GNUTLS_PRIVKEY_FLAG_CA: The generated private key is going to be used as a CA (relevant for RSA-PSS keys).
##  @GNUTLS_PRIVKEY_FLAG_EXPORT_COMPAT: Keys generated or imported as provable require an extended format which cannot be read by previous versions
##    of gnutls or other applications. By setting this flag the key will be exported in a backwards compatible way,
##    even if the information about the seed used will be lost.
##
##  Enumeration of different certificate import flags.
##

type
  gnutls_privkey_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE = 1, GNUTLS_PRIVKEY_IMPORT_COPY = 1 shl 1,
    GNUTLS_PRIVKEY_DISABLE_CALLBACKS = 1 shl 2,
    GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA = 1 shl 4,
    GNUTLS_PRIVKEY_FLAG_PROVABLE = 1 shl 5,
    GNUTLS_PRIVKEY_FLAG_EXPORT_COMPAT = 1 shl 6,
    GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS = 1 shl 7,
    GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE = 1 shl 8, GNUTLS_PRIVKEY_FLAG_CA = 1 shl 9


proc gnutls_privkey_import_pkcs11*(pkey: gnutls_privkey_t;
                                  key: gnutls_pkcs11_privkey_t; flags: cuint): cint {.
    importc: "gnutls_privkey_import_pkcs11", gnutls_import.}
proc gnutls_privkey_import_x509*(pkey: gnutls_privkey_t;
                                key: gnutls_x509_privkey_t; flags: cuint): cint {.
    importc: "gnutls_privkey_import_x509", gnutls_import.}
proc gnutls_privkey_import_openpgp*(pkey: gnutls_privkey_t;
                                   key: gnutls_openpgp_privkey_t; flags: cuint): cint {.
    importc: "gnutls_privkey_import_openpgp", gnutls_import.}
proc gnutls_privkey_export_x509*(pkey: gnutls_privkey_t;
                                key: ptr gnutls_x509_privkey_t): cint {.
    importc: "gnutls_privkey_export_x509", gnutls_import.}
proc gnutls_privkey_export_openpgp*(pkey: gnutls_privkey_t;
                                   key: ptr gnutls_openpgp_privkey_t): cint {.
    importc: "gnutls_privkey_export_openpgp", gnutls_import.}
proc gnutls_privkey_export_pkcs11*(pkey: gnutls_privkey_t;
                                  key: ptr gnutls_pkcs11_privkey_t): cint {.
    importc: "gnutls_privkey_export_pkcs11", gnutls_import.}
proc gnutls_privkey_import_openpgp_raw*(pkey: gnutls_privkey_t;
                                       data: ptr gnutls_datum_t;
                                       format: gnutls_openpgp_crt_fmt_t;
                                       keyid: gnutls_openpgp_keyid_t;
                                       password: cstring): cint {.
    importc: "gnutls_privkey_import_openpgp_raw", gnutls_import.}

proc gnutls_privkey_import_x509_raw*(pkey: gnutls_privkey_t;
                                    data: ptr gnutls_datum_t;
                                    format: gnutls_x509_crt_fmt_t;
                                    password: cstring; flags: cuint): cint {.
    importc: "gnutls_privkey_import_x509_raw", gnutls_import.}

proc gnutls_privkey_import_tpm_raw*(pkey: gnutls_privkey_t;
                                   fdata: ptr gnutls_datum_t;
                                   format: gnutls_tpmkey_fmt_t;
                                   srk_password: cstring; key_password: cstring;
                                   flags: cuint): cint {.
    importc: "gnutls_privkey_import_tpm_raw", gnutls_import.}
proc gnutls_privkey_import_tpm_url*(pkey: gnutls_privkey_t; url: cstring;
                                   srk_password: cstring; key_password: cstring;
                                   flags: cuint): cint {.
    importc: "gnutls_privkey_import_tpm_url", gnutls_import.}
proc gnutls_privkey_import_url*(key: gnutls_privkey_t; url: cstring; flags: cuint): cint {.
    importc: "gnutls_privkey_import_url", gnutls_import.}

template gnutls_privkey_import_pkcs11_url*(key, url: untyped): untyped =
  gnutls_privkey_import_url(key, url, 0)

proc gnutls_privkey_import_ext*(pkey: gnutls_privkey_t; pk: gnutls_pk_algorithm_t;
                               userdata: pointer;
                               sign_func: gnutls_privkey_sign_func;
                               decrypt_func: gnutls_privkey_decrypt_func;
                               flags: cuint): cint {.
    importc: "gnutls_privkey_import_ext", gnutls_import.}
proc gnutls_privkey_import_ext2*(pkey: gnutls_privkey_t; pk: gnutls_pk_algorithm_t;
                                userdata: pointer;
                                sign_func: gnutls_privkey_sign_func;
                                decrypt_func: gnutls_privkey_decrypt_func;
                                deinit_func: gnutls_privkey_deinit_func;
                                flags: cuint): cint {.
    importc: "gnutls_privkey_import_ext2", gnutls_import.}
proc gnutls_privkey_import_ext3*(pkey: gnutls_privkey_t; userdata: pointer;
                                sign_func: gnutls_privkey_sign_func;
                                decrypt_func: gnutls_privkey_decrypt_func;
                                deinit_func: gnutls_privkey_deinit_func;
                                info_func: gnutls_privkey_info_func; flags: cuint): cint {.
    importc: "gnutls_privkey_import_ext3", gnutls_import.}
proc gnutls_privkey_import_ext4*(pkey: gnutls_privkey_t; userdata: pointer;
                                sign_data_func: gnutls_privkey_sign_data_func;
                                sign_hash_func: gnutls_privkey_sign_hash_func;
                                decrypt_func: gnutls_privkey_decrypt_func;
                                deinit_func: gnutls_privkey_deinit_func;
                                info_func: gnutls_privkey_info_func; flags: cuint): cint {.
    importc: "gnutls_privkey_import_ext4", gnutls_import.}
proc gnutls_privkey_import_dsa_raw*(key: gnutls_privkey_t; p: ptr gnutls_datum_t;
                                   q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                   y: ptr gnutls_datum_t; x: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_import_dsa_raw", gnutls_import.}
proc gnutls_privkey_import_rsa_raw*(key: gnutls_privkey_t; m: ptr gnutls_datum_t;
                                   e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
                                   p: ptr gnutls_datum_t; q: ptr gnutls_datum_t;
                                   u: ptr gnutls_datum_t; e1: ptr gnutls_datum_t;
                                   e2: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_import_rsa_raw", gnutls_import.}
proc gnutls_privkey_import_ecc_raw*(key: gnutls_privkey_t;
                                   curve: gnutls_ecc_curve_t;
                                   x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                   k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_import_ecc_raw", gnutls_import.}
proc gnutls_privkey_import_gost_raw*(key: gnutls_privkey_t;
                                    curve: gnutls_ecc_curve_t;
                                    digest: gnutls_digest_algorithm_t;
                                    paramset: gnutls_gost_paramset_t;
                                    x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                    k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_import_gost_raw", gnutls_import.}
proc gnutls_privkey_sign_data*(signer: gnutls_privkey_t;
                              hash: gnutls_digest_algorithm_t; flags: cuint;
                              data: ptr gnutls_datum_t;
                              signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_sign_data", gnutls_import.}
proc gnutls_privkey_sign_data2*(signer: gnutls_privkey_t;
                               algo: gnutls_sign_algorithm_t; flags: cuint;
                               data: ptr gnutls_datum_t;
                               signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_sign_data2", gnutls_import.}
template gnutls_privkey_sign_raw_data*(key, flags, data, sig: untyped): untyped =
  gnutls_privkey_sign_hash(key, 0, GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA, data, sig)

proc gnutls_privkey_sign_hash*(signer: gnutls_privkey_t;
                              hash_algo: gnutls_digest_algorithm_t; flags: cuint;
                              hash_data: ptr gnutls_datum_t;
                              signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_sign_hash", gnutls_import.}
proc gnutls_privkey_sign_hash2*(signer: gnutls_privkey_t;
                               algo: gnutls_sign_algorithm_t; flags: cuint;
                               hash_data: ptr gnutls_datum_t;
                               signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_sign_hash2", gnutls_import.}
proc gnutls_privkey_decrypt_data*(key: gnutls_privkey_t; flags: cuint;
                                 ciphertext: ptr gnutls_datum_t;
                                 plaintext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_decrypt_data", gnutls_import.}
proc gnutls_privkey_decrypt_data2*(key: gnutls_privkey_t; flags: cuint;
                                  ciphertext: ptr gnutls_datum_t;
                                  plaintext: ptr cuchar; plaintext_size: csize): cint {.
    importc: "gnutls_privkey_decrypt_data2", gnutls_import.}
proc gnutls_privkey_export_rsa_raw*(key: gnutls_privkey_t; m: ptr gnutls_datum_t;
                                   e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
                                   p: ptr gnutls_datum_t; q: ptr gnutls_datum_t;
                                   u: ptr gnutls_datum_t; e1: ptr gnutls_datum_t;
                                   e2: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_export_rsa_raw", gnutls_import.}
proc gnutls_privkey_export_rsa_raw2*(key: gnutls_privkey_t; m: ptr gnutls_datum_t;
                                    e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
                                    p: ptr gnutls_datum_t; q: ptr gnutls_datum_t;
                                    u: ptr gnutls_datum_t; e1: ptr gnutls_datum_t;
                                    e2: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_privkey_export_rsa_raw2", gnutls_import.}
proc gnutls_privkey_export_dsa_raw*(key: gnutls_privkey_t; p: ptr gnutls_datum_t;
                                   q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                   y: ptr gnutls_datum_t; x: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_export_dsa_raw", gnutls_import.}
proc gnutls_privkey_export_dsa_raw2*(key: gnutls_privkey_t; p: ptr gnutls_datum_t;
                                    q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                    y: ptr gnutls_datum_t; x: ptr gnutls_datum_t;
                                    flags: cuint): cint {.
    importc: "gnutls_privkey_export_dsa_raw2", gnutls_import.}
proc gnutls_privkey_export_ecc_raw*(key: gnutls_privkey_t;
                                   curve: ptr gnutls_ecc_curve_t;
                                   x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                   k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_privkey_export_ecc_raw", gnutls_import.}
proc gnutls_privkey_export_ecc_raw2*(key: gnutls_privkey_t;
                                    curve: ptr gnutls_ecc_curve_t;
                                    x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                    k: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_privkey_export_ecc_raw2", gnutls_import.}
proc gnutls_privkey_export_gost_raw2*(key: gnutls_privkey_t;
                                     curve: ptr gnutls_ecc_curve_t;
                                     digest: ptr gnutls_digest_algorithm_t;
                                     paramset: ptr gnutls_gost_paramset_t;
                                     x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
                                     k: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_privkey_export_gost_raw2", gnutls_import.}
proc gnutls_x509_crt_privkey_sign*(crt: gnutls_x509_crt_t;
                                  issuer: gnutls_x509_crt_t;
                                  issuer_key: gnutls_privkey_t;
                                  dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_privkey_sign", gnutls_import.}
proc gnutls_x509_crl_privkey_sign*(crl: gnutls_x509_crl_t;
                                  issuer: gnutls_x509_crt_t;
                                  issuer_key: gnutls_privkey_t;
                                  dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crl_privkey_sign", gnutls_import.}
proc gnutls_x509_crq_privkey_sign*(crq: gnutls_x509_crq_t; key: gnutls_privkey_t;
                                  dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crq_privkey_sign", gnutls_import.}
## *
##  gnutls_pcert_st:
##  @pubkey: public key of parsed certificate.
##  @cert: certificate itself of parsed certificate
##  @type: type of certificate, a #gnutls_certificate_type_t type.
##
##  A parsed certificate.
##

type
  gnutls_pcert_st* {.bycopy.} = object
    pubkey*: gnutls_pubkey_t
    cert*: gnutls_datum_t
    `type`*: gnutls_certificate_type_t


##  This flag is unused/ignored

const
  GNUTLS_PCERT_NO_CERT* = 1

proc gnutls_pcert_import_x509*(pcert: ptr gnutls_pcert_st; crt: gnutls_x509_crt_t;
                              flags: cuint): cint {.
    importc: "gnutls_pcert_import_x509", gnutls_import.}
proc gnutls_pcert_import_x509_list*(pcert: ptr gnutls_pcert_st;
                                   crt: ptr gnutls_x509_crt_t; ncrt: ptr cuint;
                                   flags: cuint): cint {.
    importc: "gnutls_pcert_import_x509_list", gnutls_import.}
proc gnutls_pcert_export_x509*(pcert: ptr gnutls_pcert_st;
                              crt: ptr gnutls_x509_crt_t): cint {.
    importc: "gnutls_pcert_export_x509", gnutls_import.}
proc gnutls_pcert_list_import_x509_raw*(pcerts: ptr gnutls_pcert_st;
                                       pcert_max: ptr cuint;
                                       data: ptr gnutls_datum_t;
                                       format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pcert_list_import_x509_raw", gnutls_import.}
proc gnutls_pcert_list_import_x509_file*(pcert_list: ptr gnutls_pcert_st;
                                        pcert_list_size: ptr cuint; file: cstring;
                                        format: gnutls_x509_crt_fmt_t;
                                        pin_fn: gnutls_pin_callback_t;
                                        pin_fn_userdata: pointer; flags: cuint): cint {.
    importc: "gnutls_pcert_list_import_x509_file", gnutls_import.}
proc gnutls_pcert_import_x509_raw*(pcert: ptr gnutls_pcert_st;
                                  cert: ptr gnutls_datum_t;
                                  format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_pcert_import_x509_raw", gnutls_import.}
proc gnutls_pcert_import_openpgp_raw*(pcert: ptr gnutls_pcert_st;
                                     cert: ptr gnutls_datum_t;
                                     format: gnutls_openpgp_crt_fmt_t;
                                     keyid: gnutls_openpgp_keyid_t; flags: cuint): cint {.
    importc: "gnutls_pcert_import_openpgp_raw", gnutls_import.}
proc gnutls_pcert_import_openpgp*(pcert: ptr gnutls_pcert_st;
                                 crt: gnutls_openpgp_crt_t; flags: cuint): cint {.
    importc: "gnutls_pcert_import_openpgp", gnutls_import.}
proc gnutls_pcert_export_openpgp*(pcert: ptr gnutls_pcert_st;
                                 crt: ptr gnutls_openpgp_crt_t): cint {.
    importc: "gnutls_pcert_export_openpgp", gnutls_import.}
proc gnutls_pcert_deinit*(pcert: ptr gnutls_pcert_st) {.
    importc: "gnutls_pcert_deinit", gnutls_import.}
proc gnutls_pcert_import_rawpk*(pcert: ptr gnutls_pcert_st; key: gnutls_pubkey_t;
                               flags: cuint): cint {.
    importc: "gnutls_pcert_import_rawpk", gnutls_import.}
proc gnutls_pcert_import_rawpk_raw*(pcert: ptr gnutls_pcert_st;
                                   rawpubkey: ptr gnutls_datum_t;
                                   format: gnutls_x509_crt_fmt_t;
                                   key_usage: cuint; flags: cuint): cint {.
    importc: "gnutls_pcert_import_rawpk_raw", gnutls_import.}
##  For certificate credentials
##  This is the same as gnutls_certificate_retrieve_function()
##  but retrieves a gnutls_pcert_st which requires much less processing
##  within the library.
##

type
  gnutls_certificate_retrieve_function2* = proc (a1: gnutls_session_t;
      req_ca_rdn: ptr gnutls_datum_t; nreqs: cint;
      pk_algos: ptr gnutls_pk_algorithm_t; pk_algos_length: cint;
      a6: ptr ptr gnutls_pcert_st; pcert_length: ptr cuint;
      privkey: ptr gnutls_privkey_t): cint

proc gnutls_certificate_set_retrieve_function2*(
    cred: gnutls_certificate_credentials_t;
    `func`: ptr gnutls_certificate_retrieve_function2) {.
    importc: "gnutls_certificate_set_retrieve_function2", gnutls_import.}
type
  gnutls_cert_retr_st* {.bycopy.} = object
    version*: cuint            ##  set to 1
    cred*: gnutls_certificate_credentials_t
    req_ca_rdn*: ptr gnutls_datum_t
    nreqs*: cuint
    pk_algos*: ptr gnutls_pk_algorithm_t
    pk_algos_length*: cuint    ##  other fields may be added if version is > 1
    padding*: array[64, cuchar]


##  When the callback sets this value, gnutls will deinitialize the given
##  values after use

const
  GNUTLS_CERT_RETR_DEINIT_ALL* = 1

type
  gnutls_certificate_retrieve_function3* = proc (a1: gnutls_session_t;
      info: ptr gnutls_cert_retr_st; certs: ptr ptr gnutls_pcert_st;
      pcert_length: ptr cuint; ocsp: ptr ptr gnutls_ocsp_data_st;
      ocsp_length: ptr cuint; privkey: ptr gnutls_privkey_t; flags: ptr cuint): cint

proc gnutls_certificate_set_retrieve_function3*(
    cred: gnutls_certificate_credentials_t;
    `func`: ptr gnutls_certificate_retrieve_function3) {.
    importc: "gnutls_certificate_set_retrieve_function3", gnutls_import.}
proc gnutls_certificate_set_key*(res: gnutls_certificate_credentials_t;
                                names: cstringArray; names_size: cint;
                                pcert_list: ptr gnutls_pcert_st;
                                pcert_list_size: cint; key: gnutls_privkey_t): cint {.
    importc: "gnutls_certificate_set_key", gnutls_import.}
proc gnutls_pubkey_print*(pubkey: gnutls_pubkey_t;
                         format: gnutls_certificate_print_formats_t;
                         `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pubkey_print", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
