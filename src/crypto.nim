import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2008-2012 Free Software Foundation, Inc.
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
  gnutls_cipher_hd_t* = ptr api_cipher_hd_st

proc gnutls_cipher_init*(handle: ptr gnutls_cipher_hd_t;
                        cipher: gnutls_cipher_algorithm_t;
                        key: ptr gnutls_datum_t; iv: ptr gnutls_datum_t): cint {.
    importc: "gnutls_cipher_init", gnutls_import.}
proc gnutls_cipher_encrypt*(handle: gnutls_cipher_hd_t; text: pointer; textlen: csize): cint {.
    importc: "gnutls_cipher_encrypt", gnutls_import.}
proc gnutls_cipher_decrypt*(handle: gnutls_cipher_hd_t; ciphertext: pointer;
                           ciphertextlen: csize): cint {.
    importc: "gnutls_cipher_decrypt", gnutls_import.}
proc gnutls_cipher_decrypt2*(handle: gnutls_cipher_hd_t; ciphertext: pointer;
                            ciphertextlen: csize; text: pointer; textlen: csize): cint {.
    importc: "gnutls_cipher_decrypt2", gnutls_import.}
proc gnutls_cipher_encrypt2*(handle: gnutls_cipher_hd_t; text: pointer;
                            textlen: csize; ciphertext: pointer;
                            ciphertextlen: csize): cint {.
    importc: "gnutls_cipher_encrypt2", gnutls_import.}
proc gnutls_cipher_set_iv*(handle: gnutls_cipher_hd_t; iv: pointer; ivlen: csize) {.
    importc: "gnutls_cipher_set_iv", gnutls_import.}
proc gnutls_cipher_tag*(handle: gnutls_cipher_hd_t; tag: pointer; tag_size: csize): cint {.
    importc: "gnutls_cipher_tag", gnutls_import.}
proc gnutls_cipher_add_auth*(handle: gnutls_cipher_hd_t; text: pointer;
                            text_size: csize): cint {.
    importc: "gnutls_cipher_add_auth", gnutls_import.}
proc gnutls_cipher_deinit*(handle: gnutls_cipher_hd_t) {.
    importc: "gnutls_cipher_deinit", gnutls_import.}
proc gnutls_cipher_get_block_size*(algorithm: gnutls_cipher_algorithm_t): cuint {.
    importc: "gnutls_cipher_get_block_size", gnutls_import.}
proc gnutls_cipher_get_iv_size*(algorithm: gnutls_cipher_algorithm_t): cuint {.
    importc: "gnutls_cipher_get_iv_size", gnutls_import.}
proc gnutls_cipher_get_tag_size*(algorithm: gnutls_cipher_algorithm_t): cuint {.
    importc: "gnutls_cipher_get_tag_size", gnutls_import.}
##  AEAD API
##

type
  api_aead_cipher_hd_st* {.bycopy.} = object
  gnutls_aead_cipher_hd_t* = ptr api_aead_cipher_hd_st

proc gnutls_aead_cipher_init*(handle: ptr gnutls_aead_cipher_hd_t;
                             cipher: gnutls_cipher_algorithm_t;
                             key: ptr gnutls_datum_t): cint {.
    importc: "gnutls_aead_cipher_init", gnutls_import.}
proc gnutls_aead_cipher_decrypt*(handle: gnutls_aead_cipher_hd_t; nonce: pointer;
                                nonce_len: csize; auth: pointer; auth_len: csize;
                                tag_size: csize; ctext: pointer; ctext_len: csize;
                                ptext: pointer; ptext_len: ptr csize): cint {.
    importc: "gnutls_aead_cipher_decrypt", gnutls_import.}
proc gnutls_aead_cipher_encrypt*(handle: gnutls_aead_cipher_hd_t; nonce: pointer;
                                nonce_len: csize; auth: pointer; auth_len: csize;
                                tag_size: csize; ptext: pointer; ptext_len: csize;
                                ctext: pointer; ctext_len: ptr csize): cint {.
    importc: "gnutls_aead_cipher_encrypt", gnutls_import.}
proc gnutls_aead_cipher_encryptv*(handle: gnutls_aead_cipher_hd_t; nonce: pointer;
                                 nonce_len: csize; auth_iov: ptr giovec_t;
                                 auth_iovcnt: cint; tag_size: csize;
                                 iov: ptr giovec_t; iovcnt: cint; ctext: pointer;
                                 ctext_len: ptr csize): cint {.
    importc: "gnutls_aead_cipher_encryptv", gnutls_import.}
proc gnutls_aead_cipher_deinit*(handle: gnutls_aead_cipher_hd_t) {.
    importc: "gnutls_aead_cipher_deinit", gnutls_import.}
##  Hash - MAC API

type
  hash_hd_st* = object
  hmac_hd_st* = object
  gnutls_hash_hd_t* = ptr hash_hd_st
  gnutls_hmac_hd_t* = ptr hmac_hd_st

proc gnutls_mac_get_nonce_size*(algorithm: gnutls_mac_algorithm_t): csize {.
    importc: "gnutls_mac_get_nonce_size", gnutls_import.}
proc gnutls_hmac_init*(dig: ptr gnutls_hmac_hd_t; algorithm: gnutls_mac_algorithm_t;
                      key: pointer; keylen: csize): cint {.
    importc: "gnutls_hmac_init", gnutls_import.}
proc gnutls_hmac_set_nonce*(handle: gnutls_hmac_hd_t; nonce: pointer;
                           nonce_len: csize) {.importc: "gnutls_hmac_set_nonce",
    gnutls_import.}
proc gnutls_hmac*(handle: gnutls_hmac_hd_t; text: pointer; textlen: csize): cint {.
    importc: "gnutls_hmac", gnutls_import.}
proc gnutls_hmac_output*(handle: gnutls_hmac_hd_t; digest: pointer) {.
    importc: "gnutls_hmac_output", gnutls_import.}
proc gnutls_hmac_deinit*(handle: gnutls_hmac_hd_t; digest: pointer) {.
    importc: "gnutls_hmac_deinit", gnutls_import.}
proc gnutls_hmac_get_len*(algorithm: gnutls_mac_algorithm_t): cuint {.
    importc: "gnutls_hmac_get_len", gnutls_import.}
proc gnutls_hmac_fast*(algorithm: gnutls_mac_algorithm_t; key: pointer;
                      keylen: csize; text: pointer; textlen: csize; digest: pointer): cint {.
    importc: "gnutls_hmac_fast", gnutls_import.}
proc gnutls_hash_init*(dig: ptr gnutls_hash_hd_t;
                      algorithm: gnutls_digest_algorithm_t): cint {.
    importc: "gnutls_hash_init", gnutls_import.}
proc gnutls_hash*(handle: gnutls_hash_hd_t; text: pointer; textlen: csize): cint {.
    importc: "gnutls_hash", gnutls_import.}
proc gnutls_hash_output*(handle: gnutls_hash_hd_t; digest: pointer) {.
    importc: "gnutls_hash_output", gnutls_import.}
proc gnutls_hash_deinit*(handle: gnutls_hash_hd_t; digest: pointer) {.
    importc: "gnutls_hash_deinit", gnutls_import.}
proc gnutls_hash_get_len*(algorithm: gnutls_digest_algorithm_t): cuint {.
    importc: "gnutls_hash_get_len", gnutls_import.}
proc gnutls_hash_fast*(algorithm: gnutls_digest_algorithm_t; text: pointer;
                      textlen: csize; digest: pointer): cint {.
    importc: "gnutls_hash_fast", gnutls_import.}
##  register ciphers
## *
##  gnutls_rnd_level_t:
##  @GNUTLS_RND_NONCE: Non-predictable random number.  Fatal in parts
##    of session if broken, i.e., vulnerable to statistical analysis.
##  @GNUTLS_RND_RANDOM: Pseudo-random cryptographic random number.
##    Fatal in session if broken. Example use: temporal keys.
##  @GNUTLS_RND_KEY: Fatal in many sessions if broken. Example use:
##    Long-term keys.
##
##  Enumeration of random quality levels.
##

type
  gnutls_rnd_level_t* {.size: sizeof(cint).} = enum
    GNUTLS_RND_NONCE = 0, GNUTLS_RND_RANDOM = 1, GNUTLS_RND_KEY = 2


proc gnutls_rnd*(level: gnutls_rnd_level_t; data: pointer; len: csize): cint {.
    importc: "gnutls_rnd", gnutls_import.}
proc gnutls_rnd_refresh*() {.importc: "gnutls_rnd_refresh", gnutls_import.}
##  API to override ciphers and MAC algorithms
##

type
  gnutls_cipher_init_func* = proc (a1: gnutls_cipher_algorithm_t; ctx: ptr pointer;
                                enc: cint): cint
  gnutls_cipher_setkey_func* = proc (ctx: pointer; key: pointer; keysize: csize): cint

##  old style ciphers

type
  gnutls_cipher_setiv_func* = proc (ctx: pointer; iv: pointer; ivsize: csize): cint
  gnutls_cipher_encrypt_func* = proc (ctx: pointer; plain: pointer; plainsize: csize;
                                   encr: pointer; encrsize: csize): cint
  gnutls_cipher_decrypt_func* = proc (ctx: pointer; encr: pointer; encrsize: csize;
                                   plain: pointer; plainsize: csize): cint

##  aead ciphers

type
  gnutls_cipher_auth_func* = proc (ctx: pointer; data: pointer; datasize: csize): cint
  gnutls_cipher_tag_func* = proc (ctx: pointer; tag: pointer; tagsize: csize)
  gnutls_cipher_aead_encrypt_func* = proc (ctx: pointer; nonce: pointer;
                                        noncesize: csize; auth: pointer;
                                        authsize: csize; tag_size: csize;
                                        plain: pointer; plainsize: csize;
                                        encr: pointer; encrsize: csize): cint
  gnutls_cipher_aead_decrypt_func* = proc (ctx: pointer; nonce: pointer;
                                        noncesize: csize; auth: pointer;
                                        authsize: csize; tag_size: csize;
                                        encr: pointer; encrsize: csize;
                                        plain: pointer; plainsize: csize): cint
  gnutls_cipher_deinit_func* = proc (ctx: pointer)

proc gnutls_crypto_register_cipher*(algorithm: gnutls_cipher_algorithm_t;
                                   priority: cint; init: gnutls_cipher_init_func;
                                   setkey: gnutls_cipher_setkey_func;
                                   setiv: gnutls_cipher_setiv_func;
                                   encrypt: gnutls_cipher_encrypt_func;
                                   decrypt: gnutls_cipher_decrypt_func;
                                   deinit: gnutls_cipher_deinit_func): cint {.
    importc: "gnutls_crypto_register_cipher", gnutls_import.}
proc gnutls_crypto_register_aead_cipher*(algorithm: gnutls_cipher_algorithm_t;
                                        priority: cint;
                                        init: gnutls_cipher_init_func;
                                        setkey: gnutls_cipher_setkey_func;
    aead_encrypt: gnutls_cipher_aead_encrypt_func; aead_decrypt: gnutls_cipher_aead_decrypt_func;
                                        deinit: gnutls_cipher_deinit_func): cint {.
    importc: "gnutls_crypto_register_aead_cipher", gnutls_import.}
type
  gnutls_mac_init_func* = proc (a1: gnutls_mac_algorithm_t; ctx: ptr pointer): cint
  gnutls_mac_setkey_func* = proc (ctx: pointer; key: pointer; keysize: csize): cint
  gnutls_mac_setnonce_func* = proc (ctx: pointer; nonce: pointer; noncesize: csize): cint
  gnutls_mac_hash_func* = proc (ctx: pointer; text: pointer; textsize: csize): cint
  gnutls_mac_output_func* = proc (src_ctx: pointer; digest: pointer; digestsize: csize): cint
  gnutls_mac_deinit_func* = proc (ctx: pointer)
  gnutls_mac_fast_func* = proc (a1: gnutls_mac_algorithm_t; nonce: pointer;
                             nonce_size: csize; key: pointer; keysize: csize;
                             text: pointer; textsize: csize; digest: pointer): cint

proc gnutls_crypto_register_mac*(mac: gnutls_mac_algorithm_t; priority: cint;
                                init: gnutls_mac_init_func;
                                setkey: gnutls_mac_setkey_func;
                                setnonce: gnutls_mac_setnonce_func;
                                hash: gnutls_mac_hash_func;
                                output: gnutls_mac_output_func;
                                deinit: gnutls_mac_deinit_func;
                                hash_fast: gnutls_mac_fast_func): cint {.
    importc: "gnutls_crypto_register_mac", gnutls_import.}
type
  gnutls_digest_init_func* = proc (a1: gnutls_digest_algorithm_t; ctx: ptr pointer): cint
  gnutls_digest_hash_func* = proc (ctx: pointer; text: pointer; textsize: csize): cint
  gnutls_digest_output_func* = proc (src_ctx: pointer; digest: pointer;
                                  digestsize: csize): cint
  gnutls_digest_deinit_func* = proc (ctx: pointer)
  gnutls_digest_fast_func* = proc (a1: gnutls_digest_algorithm_t; text: pointer;
                                textsize: csize; digest: pointer): cint

proc gnutls_crypto_register_digest*(digest: gnutls_digest_algorithm_t;
                                   priority: cint; init: gnutls_digest_init_func;
                                   hash: gnutls_digest_hash_func;
                                   output: gnutls_digest_output_func;
                                   deinit: gnutls_digest_deinit_func;
                                   hash_fast: gnutls_digest_fast_func): cint {.
    importc: "gnutls_crypto_register_digest", gnutls_import.}
##  RSA-PKCS#1 1.5 helper functions

proc gnutls_encode_ber_digest_info*(hash: gnutls_digest_algorithm_t;
                                   digest: ptr gnutls_datum_t;
                                   output: ptr gnutls_datum_t): cint {.
    importc: "gnutls_encode_ber_digest_info", gnutls_import.}
proc gnutls_decode_ber_digest_info*(info: ptr gnutls_datum_t;
                                   hash: ptr gnutls_digest_algorithm_t;
                                   digest: ptr cuchar; digest_size: ptr cuint): cint {.
    importc: "gnutls_decode_ber_digest_info", gnutls_import.}
proc gnutls_decode_rs_value*(sig_value: ptr gnutls_datum_t; r: ptr gnutls_datum_t;
                            s: ptr gnutls_datum_t): cint {.
    importc: "gnutls_decode_rs_value", gnutls_import.}
proc gnutls_encode_rs_value*(sig_value: ptr gnutls_datum_t; r: ptr gnutls_datum_t;
                            s: ptr gnutls_datum_t): cint {.
    importc: "gnutls_encode_rs_value", gnutls_import.}
proc gnutls_encode_gost_rs_value*(sig_value: ptr gnutls_datum_t;
                                 r: ptr gnutls_datum_t; s: ptr gnutls_datum_t): cint {.
    importc: "gnutls_encode_gost_rs_value", gnutls_import.}
proc gnutls_decode_gost_rs_value*(sig_value: ptr gnutls_datum_t;
                                 r: ptr gnutls_datum_t; s: ptr gnutls_datum_t): cint {.
    importc: "gnutls_decode_gost_rs_value", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
