import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
##  -*- c -*-
##  Copyright (C) 2000-2016 Free Software Foundation, Inc.
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
##  This file contains the types and prototypes for all the
##  high level functionality of the gnutls main library.
##
##  If the optional C++ binding was built, it is available in
##  gnutls/gnutlsxx.h.
##
##  The openssl compatibility layer (which is under the GNU GPL
##  license) is in gnutls/openssl.h.
##
##  The low level cipher functionality is in gnutls/crypto.h.
##

##  Get size_t.

##  Get ssize_t.

##  *INDENT-OFF*

##  *INDENT-ON*

##  Get time_t.

##  *INDENT-OFF*

##  *INDENT-ON*

const
  GNUTLS_VERSION* = "3.6.6"
  GNUTLS_VERSION_MAJOR* = 3
  GNUTLS_VERSION_MINOR* = 6
  GNUTLS_VERSION_PATCH* = 6
  GNUTLS_VERSION_NUMBER* = 0x00030606

##  Use the following definition globally in your program to disable
##  implicit initialization of gnutls.
## #define GNUTLS_SKIP_GLOBAL_INIT int _gnutls_global_init_skip(void); \
##     int _gnutls_global_init_skip(void) {return 1;}
## *
##  gnutls_cipher_algorithm_t:
##  @GNUTLS_CIPHER_UNKNOWN: Value to identify an unknown/unsupported algorithm.
##  @GNUTLS_CIPHER_NULL: The NULL (identity) encryption algorithm.
##  @GNUTLS_CIPHER_ARCFOUR_128: ARCFOUR stream cipher with 128-bit keys.
##  @GNUTLS_CIPHER_3DES_CBC: 3DES in CBC mode.
##  @GNUTLS_CIPHER_AES_128_CBC: AES in CBC mode with 128-bit keys.
##  @GNUTLS_CIPHER_AES_192_CBC: AES in CBC mode with 192-bit keys.
##  @GNUTLS_CIPHER_AES_256_CBC: AES in CBC mode with 256-bit keys.
##  @GNUTLS_CIPHER_AES_128_CFB8: AES in CFB8 mode with 128-bit keys.
##  @GNUTLS_CIPHER_AES_192_CFB8: AES in CFB8 mode with 192-bit keys.
##  @GNUTLS_CIPHER_AES_256_CFB8: AES in CFB8 mode with 256-bit keys.
##  @GNUTLS_CIPHER_ARCFOUR_40: ARCFOUR stream cipher with 40-bit keys.
##  @GNUTLS_CIPHER_CAMELLIA_128_CBC: Camellia in CBC mode with 128-bit keys.
##  @GNUTLS_CIPHER_CAMELLIA_192_CBC: Camellia in CBC mode with 192-bit keys.
##  @GNUTLS_CIPHER_CAMELLIA_256_CBC: Camellia in CBC mode with 256-bit keys.
##  @GNUTLS_CIPHER_RC2_40_CBC: RC2 in CBC mode with 40-bit keys.
##  @GNUTLS_CIPHER_DES_CBC: DES in CBC mode (56-bit keys).
##  @GNUTLS_CIPHER_AES_128_GCM: AES in GCM mode with 128-bit keys.
##  @GNUTLS_CIPHER_AES_256_GCM: AES in GCM mode with 256-bit keys.
##  @GNUTLS_CIPHER_AES_128_CCM: AES in CCM mode with 128-bit keys.
##  @GNUTLS_CIPHER_AES_256_CCM: AES in CCM mode with 256-bit keys.
##  @GNUTLS_CIPHER_AES_128_CCM_8: AES in CCM mode with 64-bit tag and 128-bit keys.
##  @GNUTLS_CIPHER_AES_256_CCM_8: AES in CCM mode with 64-bit tag and 256-bit keys.
##  @GNUTLS_CIPHER_CAMELLIA_128_GCM: CAMELLIA in GCM mode with 128-bit keys.
##  @GNUTLS_CIPHER_CAMELLIA_256_GCM: CAMELLIA in GCM mode with 256-bit keys.
##  @GNUTLS_CIPHER_SALSA20_256: Salsa20 with 256-bit keys.
##  @GNUTLS_CIPHER_ESTREAM_SALSA20_256: Estream's Salsa20 variant with 256-bit keys.
##  @GNUTLS_CIPHER_CHACHA20_POLY1305: The Chacha20 cipher with the Poly1305 authenticator (AEAD).
##  @GNUTLS_CIPHER_GOST28147_TC26Z_CFB: GOST 28147-89 (Magma) cipher in CFB mode with TC26 Z S-box.
##  @GNUTLS_CIPHER_GOST28147_CPA_CFB: GOST 28147-89 (Magma) cipher in CFB mode with CryptoPro A S-box.
##  @GNUTLS_CIPHER_GOST28147_CPB_CFB: GOST 28147-89 (Magma) cipher in CFB mode with CryptoPro B S-box.
##  @GNUTLS_CIPHER_GOST28147_CPC_CFB: GOST 28147-89 (Magma) cipher in CFB mode with CryptoPro C S-box.
##  @GNUTLS_CIPHER_GOST28147_CPD_CFB: GOST 28147-89 (Magma) cipher in CFB mode with CryptoPro D S-box.
##  @GNUTLS_CIPHER_IDEA_PGP_CFB: IDEA in CFB mode (placeholder - unsupported).
##  @GNUTLS_CIPHER_3DES_PGP_CFB: 3DES in CFB mode (placeholder - unsupported).
##  @GNUTLS_CIPHER_CAST5_PGP_CFB: CAST5 in CFB mode (placeholder - unsupported).
##  @GNUTLS_CIPHER_BLOWFISH_PGP_CFB: Blowfish in CFB mode (placeholder - unsupported).
##  @GNUTLS_CIPHER_SAFER_SK128_PGP_CFB: Safer-SK in CFB mode with 128-bit keys (placeholder - unsupported).
##  @GNUTLS_CIPHER_AES128_PGP_CFB: AES in CFB mode with 128-bit keys (placeholder - unsupported).
##  @GNUTLS_CIPHER_AES192_PGP_CFB: AES in CFB mode with 192-bit keys (placeholder - unsupported).
##  @GNUTLS_CIPHER_AES256_PGP_CFB: AES in CFB mode with 256-bit keys (placeholder - unsupported).
##  @GNUTLS_CIPHER_TWOFISH_PGP_CFB: Twofish in CFB mode (placeholder - unsupported).
##
##  Enumeration of different symmetric encryption algorithms.
##

type
  gnutls_cipher_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_CIPHER_UNKNOWN = 0, GNUTLS_CIPHER_NULL = 1, GNUTLS_CIPHER_ARCFOUR_128 = 2,
    GNUTLS_CIPHER_3DES_CBC = 3, GNUTLS_CIPHER_AES_128_CBC = 4,
    GNUTLS_CIPHER_AES_256_CBC = 5, GNUTLS_CIPHER_ARCFOUR_40 = 6,
    GNUTLS_CIPHER_CAMELLIA_128_CBC = 7, GNUTLS_CIPHER_CAMELLIA_256_CBC = 8,
    GNUTLS_CIPHER_AES_192_CBC = 9, GNUTLS_CIPHER_AES_128_GCM = 10,
    GNUTLS_CIPHER_AES_256_GCM = 11, GNUTLS_CIPHER_CAMELLIA_192_CBC = 12,
    GNUTLS_CIPHER_SALSA20_256 = 13, GNUTLS_CIPHER_ESTREAM_SALSA20_256 = 14,
    GNUTLS_CIPHER_CAMELLIA_128_GCM = 15, GNUTLS_CIPHER_CAMELLIA_256_GCM = 16,
    GNUTLS_CIPHER_RC2_40_CBC = 17, GNUTLS_CIPHER_DES_CBC = 18,
    GNUTLS_CIPHER_AES_128_CCM = 19, GNUTLS_CIPHER_AES_256_CCM = 20,
    GNUTLS_CIPHER_AES_128_CCM_8 = 21, GNUTLS_CIPHER_AES_256_CCM_8 = 22,
    GNUTLS_CIPHER_CHACHA20_POLY1305 = 23, GNUTLS_CIPHER_GOST28147_TC26Z_CFB = 24,
    GNUTLS_CIPHER_GOST28147_CPA_CFB = 25, GNUTLS_CIPHER_GOST28147_CPB_CFB = 26,
    GNUTLS_CIPHER_GOST28147_CPC_CFB = 27, GNUTLS_CIPHER_GOST28147_CPD_CFB = 28,
    GNUTLS_CIPHER_AES_128_CFB8 = 29, GNUTLS_CIPHER_AES_192_CFB8 = 30, GNUTLS_CIPHER_AES_256_CFB8 = 31, ##  used only for PGP internals. Ignored in TLS/SSL
                                                                                              ##
    GNUTLS_CIPHER_IDEA_PGP_CFB = 200, GNUTLS_CIPHER_3DES_PGP_CFB = 201,
    GNUTLS_CIPHER_CAST5_PGP_CFB = 202, GNUTLS_CIPHER_BLOWFISH_PGP_CFB = 203,
    GNUTLS_CIPHER_SAFER_SK128_PGP_CFB = 204, GNUTLS_CIPHER_AES128_PGP_CFB = 205,
    GNUTLS_CIPHER_AES192_PGP_CFB = 206, GNUTLS_CIPHER_AES256_PGP_CFB = 207,
    GNUTLS_CIPHER_TWOFISH_PGP_CFB = 208

const
  GNUTLS_CIPHER_RIJNDAEL_128_CBC* = GNUTLS_CIPHER_AES_128_CBC
  GNUTLS_CIPHER_RIJNDAEL_256_CBC* = GNUTLS_CIPHER_AES_256_CBC
  GNUTLS_CIPHER_RIJNDAEL_CBC* = GNUTLS_CIPHER_AES_128_CBC
  GNUTLS_CIPHER_ARCFOUR* = GNUTLS_CIPHER_ARCFOUR_128

## *
##  gnutls_kx_algorithm_t:
##  @GNUTLS_KX_UNKNOWN: Unknown key-exchange algorithm.
##  @GNUTLS_KX_RSA: RSA key-exchange algorithm.
##  @GNUTLS_KX_DHE_DSS: DHE-DSS key-exchange algorithm.
##  @GNUTLS_KX_DHE_RSA: DHE-RSA key-exchange algorithm.
##  @GNUTLS_KX_ECDHE_RSA: ECDHE-RSA key-exchange algorithm.
##  @GNUTLS_KX_ECDHE_ECDSA: ECDHE-ECDSA key-exchange algorithm.
##  @GNUTLS_KX_ANON_DH: Anon-DH key-exchange algorithm.
##  @GNUTLS_KX_ANON_ECDH: Anon-ECDH key-exchange algorithm.
##  @GNUTLS_KX_SRP: SRP key-exchange algorithm.
##  @GNUTLS_KX_RSA_EXPORT: RSA-EXPORT key-exchange algorithm (defunc).
##  @GNUTLS_KX_SRP_RSA: SRP-RSA key-exchange algorithm.
##  @GNUTLS_KX_SRP_DSS: SRP-DSS key-exchange algorithm.
##  @GNUTLS_KX_PSK: PSK key-exchange algorithm.
##  @GNUTLS_KX_DHE_PSK: DHE-PSK key-exchange algorithm.
##  @GNUTLS_KX_ECDHE_PSK: ECDHE-PSK key-exchange algorithm.
##  @GNUTLS_KX_RSA_PSK: RSA-PSK key-exchange algorithm.
##
##  Enumeration of different key exchange algorithms.
##

type
  gnutls_kx_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_KX_UNKNOWN = 0, GNUTLS_KX_RSA = 1, GNUTLS_KX_DHE_DSS = 2,
    GNUTLS_KX_DHE_RSA = 3, GNUTLS_KX_ANON_DH = 4, GNUTLS_KX_SRP = 5,
    GNUTLS_KX_RSA_EXPORT = 6, GNUTLS_KX_SRP_RSA = 7, GNUTLS_KX_SRP_DSS = 8,
    GNUTLS_KX_PSK = 9, GNUTLS_KX_DHE_PSK = 10, GNUTLS_KX_ANON_ECDH = 11,
    GNUTLS_KX_ECDHE_RSA = 12, GNUTLS_KX_ECDHE_ECDSA = 13, GNUTLS_KX_ECDHE_PSK = 14,
    GNUTLS_KX_RSA_PSK = 15


## *
##  gnutls_params_type_t:
##  @GNUTLS_PARAMS_RSA_EXPORT: Session RSA-EXPORT parameters (defunc).
##  @GNUTLS_PARAMS_DH: Session Diffie-Hellman parameters.
##  @GNUTLS_PARAMS_ECDH: Session Elliptic-Curve Diffie-Hellman parameters.
##
##  Enumeration of different TLS session parameter types.
##

type
  gnutls_params_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_PARAMS_RSA_EXPORT = 1, GNUTLS_PARAMS_DH = 2, GNUTLS_PARAMS_ECDH = 3


## *
##  gnutls_credentials_type_t:
##  @GNUTLS_CRD_CERTIFICATE: Certificate credential.
##  @GNUTLS_CRD_ANON: Anonymous credential.
##  @GNUTLS_CRD_SRP: SRP credential.
##  @GNUTLS_CRD_PSK: PSK credential.
##  @GNUTLS_CRD_IA: IA credential.
##
##  Enumeration of different credential types.
##

type
  gnutls_credentials_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_CRD_CERTIFICATE = 1, GNUTLS_CRD_ANON, GNUTLS_CRD_SRP, GNUTLS_CRD_PSK,
    GNUTLS_CRD_IA


## *
##  gnutls_mac_algorithm_t:
##  @GNUTLS_MAC_UNKNOWN: Unknown MAC algorithm.
##  @GNUTLS_MAC_NULL: NULL MAC algorithm (empty output).
##  @GNUTLS_MAC_MD5: HMAC-MD5 algorithm.
##  @GNUTLS_MAC_SHA1: HMAC-SHA-1 algorithm.
##  @GNUTLS_MAC_RMD160: HMAC-RMD160 algorithm.
##  @GNUTLS_MAC_MD2: HMAC-MD2 algorithm.
##  @GNUTLS_MAC_SHA256: HMAC-SHA-256 algorithm.
##  @GNUTLS_MAC_SHA384: HMAC-SHA-384 algorithm.
##  @GNUTLS_MAC_SHA512: HMAC-SHA-512 algorithm.
##  @GNUTLS_MAC_SHA224: HMAC-SHA-224 algorithm.
##  @GNUTLS_MAC_MD5_SHA1: Combined MD5+SHA1 MAC placeholder.
##  @GNUTLS_MAC_GOSTR_94: HMAC GOST R 34.11-94 algorithm.
##  @GNUTLS_MAC_STREEBOG_256: HMAC GOST R 34.11-2001 (Streebog) algorithm, 256 bit.
##  @GNUTLS_MAC_STREEBOG_512: HMAC GOST R 34.11-2001 (Streebog) algorithm, 512 bit.
##  @GNUTLS_MAC_AEAD: MAC implicit through AEAD cipher.
##  @GNUTLS_MAC_UMAC_96: The UMAC-96 MAC algorithm.
##  @GNUTLS_MAC_UMAC_128: The UMAC-128 MAC algorithm.
##  @GNUTLS_MAC_AES_CMAC_128: The AES-CMAC-128 MAC algorithm.
##  @GNUTLS_MAC_AES_CMAC_256: The AES-CMAC-256 MAC algorithm.
##  @GNUTLS_MAC_SHA3_224: Reserved; unimplemented.
##  @GNUTLS_MAC_SHA3_256: Reserved; unimplemented.
##  @GNUTLS_MAC_SHA3_384: Reserved; unimplemented.
##  @GNUTLS_MAC_SHA3_512: Reserved; unimplemented.
##
##  Enumeration of different Message Authentication Code (MAC)
##  algorithms.
##

type
  gnutls_mac_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_MAC_UNKNOWN = 0, GNUTLS_MAC_NULL = 1, GNUTLS_MAC_MD5 = 2, GNUTLS_MAC_SHA1 = 3,
    GNUTLS_MAC_RMD160 = 4, GNUTLS_MAC_MD2 = 5, GNUTLS_MAC_SHA256 = 6,
    GNUTLS_MAC_SHA384 = 7, GNUTLS_MAC_SHA512 = 8, GNUTLS_MAC_SHA224 = 9, GNUTLS_MAC_SHA3_224 = 10, ##  reserved: no implementation
    GNUTLS_MAC_SHA3_256 = 11,   ##  reserved: no implementation
    GNUTLS_MAC_SHA3_384 = 12,   ##  reserved: no implementation
    GNUTLS_MAC_SHA3_512 = 13,   ##  reserved: no implementation
    GNUTLS_MAC_MD5_SHA1 = 14,   ##  reserved: no implementation
    GNUTLS_MAC_GOSTR_94 = 15, GNUTLS_MAC_STREEBOG_256 = 16, GNUTLS_MAC_STREEBOG_512 = 17, ##  If you add anything here, make sure you align with
                                                                                 ## 	   gnutls_digest_algorithm_t.
    GNUTLS_MAC_AEAD = 200,      ##  indicates that MAC is on the cipher
    GNUTLS_MAC_UMAC_96 = 201, GNUTLS_MAC_UMAC_128 = 202,
    GNUTLS_MAC_AES_CMAC_128 = 203, GNUTLS_MAC_AES_CMAC_256 = 204


## *
##  gnutls_digest_algorithm_t:
##  @GNUTLS_DIG_UNKNOWN: Unknown hash algorithm.
##  @GNUTLS_DIG_NULL: NULL hash algorithm (empty output).
##  @GNUTLS_DIG_MD5: MD5 algorithm.
##  @GNUTLS_DIG_SHA1: SHA-1 algorithm.
##  @GNUTLS_DIG_RMD160: RMD160 algorithm.
##  @GNUTLS_DIG_MD2: MD2 algorithm.
##  @GNUTLS_DIG_SHA256: SHA-256 algorithm.
##  @GNUTLS_DIG_SHA384: SHA-384 algorithm.
##  @GNUTLS_DIG_SHA512: SHA-512 algorithm.
##  @GNUTLS_DIG_SHA224: SHA-224 algorithm.
##  @GNUTLS_DIG_SHA3_224: SHA3-224 algorithm.
##  @GNUTLS_DIG_SHA3_256: SHA3-256 algorithm.
##  @GNUTLS_DIG_SHA3_384: SHA3-384 algorithm.
##  @GNUTLS_DIG_SHA3_512: SHA3-512 algorithm.
##  @GNUTLS_DIG_MD5_SHA1: Combined MD5+SHA1 algorithm.
##  @GNUTLS_DIG_GOSTR_94: GOST R 34.11-94 algorithm.
##  @GNUTLS_DIG_STREEBOG_256: GOST R 34.11-2001 (Streebog) algorithm, 256 bit.
##  @GNUTLS_DIG_STREEBOG_512: GOST R 34.11-2001 (Streebog) algorithm, 512 bit.
##
##  Enumeration of different digest (hash) algorithms.
##

type
  gnutls_digest_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_DIG_UNKNOWN = GNUTLS_MAC_UNKNOWN, GNUTLS_DIG_NULL = GNUTLS_MAC_NULL,
    GNUTLS_DIG_MD5 = GNUTLS_MAC_MD5, GNUTLS_DIG_SHA1 = GNUTLS_MAC_SHA1,
    GNUTLS_DIG_RMD160 = GNUTLS_MAC_RMD160, GNUTLS_DIG_MD2 = GNUTLS_MAC_MD2,
    GNUTLS_DIG_SHA256 = GNUTLS_MAC_SHA256, GNUTLS_DIG_SHA384 = GNUTLS_MAC_SHA384,
    GNUTLS_DIG_SHA512 = GNUTLS_MAC_SHA512, GNUTLS_DIG_SHA224 = GNUTLS_MAC_SHA224,
    GNUTLS_DIG_SHA3_224 = GNUTLS_MAC_SHA3_224,
    GNUTLS_DIG_SHA3_256 = GNUTLS_MAC_SHA3_256,
    GNUTLS_DIG_SHA3_384 = GNUTLS_MAC_SHA3_384,
    GNUTLS_DIG_SHA3_512 = GNUTLS_MAC_SHA3_512,
    GNUTLS_DIG_MD5_SHA1 = GNUTLS_MAC_MD5_SHA1,
    GNUTLS_DIG_GOSTR_94 = GNUTLS_MAC_GOSTR_94,
    GNUTLS_DIG_STREEBOG_256 = GNUTLS_MAC_STREEBOG_256,
    GNUTLS_DIG_STREEBOG_512 = GNUTLS_MAC_STREEBOG_512

const
  GNUTLS_MAC_SHA* = GNUTLS_MAC_SHA1
  GNUTLS_DIG_SHA* = GNUTLS_DIG_SHA1


##  exported for other gnutls headers. This is the maximum number of
##  algorithms (ciphers, kx or macs).
##

const
  GNUTLS_MAX_ALGORITHM_NUM* = 64
  GNUTLS_MAX_SESSION_ID_SIZE* = 32

## *
##  gnutls_compression_method_t:
##  @GNUTLS_COMP_UNKNOWN: Unknown compression method.
##  @GNUTLS_COMP_NULL: The NULL compression method (no compression).
##  @GNUTLS_COMP_DEFLATE: The DEFLATE compression method from zlib.
##  @GNUTLS_COMP_ZLIB: Same as %GNUTLS_COMP_DEFLATE.
##
##  Enumeration of different TLS compression methods.
##

type
  gnutls_compression_method_t* {.size: sizeof(cint).} = enum
    GNUTLS_COMP_UNKNOWN = 0, GNUTLS_COMP_NULL = 1, GNUTLS_COMP_DEFLATE = 2

const
  GNUTLS_COMP_ZLIB = GNUTLS_COMP_DEFLATE

## *
##  gnutls_init_flags_t:
##
##  @GNUTLS_SERVER: Connection end is a server.
##  @GNUTLS_CLIENT: Connection end is a client.
##  @GNUTLS_DATAGRAM: Connection is datagram oriented (DTLS). Since 3.0.0.
##  @GNUTLS_NONBLOCK: Connection should not block. Since 3.0.0.
##  @GNUTLS_NO_SIGNAL: In systems where SIGPIPE is delivered on send, it will be disabled. That flag has effect in systems which support the MSG_NOSIGNAL sockets flag (since 3.4.2).
##  @GNUTLS_NO_EXTENSIONS: Do not enable any TLS extensions by default (since 3.1.2). As TLS 1.2 and later require extensions this option is considered obsolete and should not be used.
##  @GNUTLS_NO_REPLAY_PROTECTION: Disable any replay protection in DTLS. This must only be used if  replay protection is achieved using other means. Since 3.2.2.
##  @GNUTLS_ALLOW_ID_CHANGE: Allow the peer to replace its certificate, or change its ID during a rehandshake. This change is often used in attacks and thus prohibited by default. Since 3.5.0.
##  @GNUTLS_ENABLE_FALSE_START: Enable the TLS false start on client side if the negotiated ciphersuites allow it. This will enable sending data prior to the handshake being complete, and may introduce a risk of crypto failure when combined with certain key exchanged; for that GnuTLS may not enable that option in ciphersuites that are known to be not safe for false start. Since 3.5.0.
##  @GNUTLS_ENABLE_EARLY_START: Under TLS1.3 allow the server to return earlier than the full handshake
##    finish; similarly to false start the handshake will be completed once data are received by the
##    client, while the server is able to transmit sooner. This is not enabled by default as it could
##    break certain existing server assumptions and use-cases. Since 3.6.4.
##  @GNUTLS_ENABLE_EARLY_DATA: Under TLS1.3 allow the server to receive early data sent as part of the initial ClientHello (0-RTT). This is not enabled by default as early data has weaker security properties than other data. Since 3.6.5.
##  @GNUTLS_FORCE_CLIENT_CERT: When in client side and only a single cert is specified, send that certificate irrespective of the issuers expected by the server. Since 3.5.0.
##  @GNUTLS_NO_TICKETS: Flag to indicate that the session should not use resumption with session tickets.
##  @GNUTLS_KEY_SHARE_TOP3: Generate key shares for the top-3 different groups which are enabled.
##    That is, as each group is associated with a key type (EC, finite field, x25519), generate
##    three keys using %GNUTLS_PK_DH, %GNUTLS_PK_EC, %GNUTLS_PK_ECDH_X25519 if all of them are enabled.
##  @GNUTLS_KEY_SHARE_TOP2: Generate key shares for the top-2 different groups which are enabled.
##    For example (ECDH + x25519). This is the default.
##  @GNUTLS_KEY_SHARE_TOP: Generate key share for the first group which is enabled.
##    For example x25519. This option is the most performant for client (less CPU spent
##    generating keys), but if the server doesn't support the advertized option it may
##    result to more roundtrips needed to discover the server's choice.
##  @GNUTLS_NO_AUTO_REKEY: Disable auto-rekeying under TLS1.3. If this option is not specified
##    gnutls will force a rekey after 2^24 records have been sent.
##  @GNUTLS_POST_HANDSHAKE_AUTH: Enable post handshake authentication for server and client. When set and
##    a server requests authentication after handshake %GNUTLS_E_REAUTH_REQUEST will be returned
##    by gnutls_record_recv(). A client should then call gnutls_reauth() to re-authenticate.
##  @GNUTLS_SAFE_PADDING_CHECK: Flag to indicate that the TLS 1.3 padding check will be done in a
##    safe way which doesn't leak the pad size based on GnuTLS processing time. This is of use to
##    applications which hide the length of transferred data via the TLS1.3 padding mechanism and
##    are already taking steps to hide the data processing time. This comes at a performance
##    penalty.
##  @GNUTLS_AUTO_REAUTH: Enable transparent re-authentication in client side when the server
##     requests to. That is, reauthentication is handled within gnutls_record_recv(), and
##     the %GNUTLS_E_REHANDSHAKE or %GNUTLS_E_REAUTH_REQUEST are not returned. This must be
##     enabled with %GNUTLS_POST_HANDSHAKE_AUTH for TLS1.3. Enabling this flag requires to restore
##     interrupted calls to gnutls_record_recv() based on the output of gnutls_record_get_direction(),
##     since gnutls_record_recv() could be interrupted when sending when this flag is enabled.
##     Note this flag may not be used if you are using the same session for sending and receiving
##     in different threads.
##  @GNUTLS_ENABLE_EARLY_DATA: Under TLS1.3 allow the server to receive early data sent as part of the initial ClientHello (0-RTT).
##     This is not enabled by default as early data has weaker security properties than other data. Since 3.6.5.
##  @GNUTLS_ENABLE_RAWPK: Allows raw public-keys to be negotiated during the handshake. Since 3.6.6.
##
##  Enumeration of different flags for gnutls_init() function. All the flags
##  can be combined except @GNUTLS_SERVER and @GNUTLS_CLIENT which are mutually
##  exclusive.
##
##  The key share options relate to the TLS 1.3 key share extension
##  which is a speculative key generation expecting that the server
##  would support the generated key.
##

type
  gnutls_init_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_SERVER = 1, GNUTLS_CLIENT = (1 shl 1), GNUTLS_DATAGRAM = (1 shl 2),
    GNUTLS_NONBLOCK = (1 shl 3), GNUTLS_NO_EXTENSIONS = (1 shl 4),
    GNUTLS_NO_REPLAY_PROTECTION = (1 shl 5), GNUTLS_NO_SIGNAL = (1 shl 6),
    GNUTLS_ALLOW_ID_CHANGE = (1 shl 7), GNUTLS_ENABLE_FALSE_START = (1 shl 8),
    GNUTLS_FORCE_CLIENT_CERT = (1 shl 9), GNUTLS_NO_TICKETS = (1 shl 10),
    GNUTLS_KEY_SHARE_TOP = (1 shl 11), GNUTLS_KEY_SHARE_TOP2 = (1 shl 12),
    GNUTLS_KEY_SHARE_TOP3 = (1 shl 13), GNUTLS_POST_HANDSHAKE_AUTH = (1 shl 14),
    GNUTLS_NO_AUTO_REKEY = (1 shl 15), GNUTLS_SAFE_PADDING_CHECK = (1 shl 16),
    GNUTLS_ENABLE_EARLY_START = (1 shl 17), GNUTLS_ENABLE_RAWPK = (1 shl 18),
    GNUTLS_AUTO_REAUTH = (1 shl 19), GNUTLS_ENABLE_EARLY_DATA = (1 shl 20)


##  compatibility defines (previous versions of gnutls
##  used defines instead of enumerated values).

#const
#  GNUTLS_SERVER* = (1)
#  GNUTLS_CLIENT* = (1 shl 1)
#  GNUTLS_DATAGRAM* = (1 shl 2)
#  GNUTLS_NONBLOCK* = (1 shl 3)
#  GNUTLS_NO_EXTENSIONS* = (1 shl 4)
#  GNUTLS_NO_REPLAY_PROTECTION* = (1 shl 5)
#  GNUTLS_NO_SIGNAL* = (1 shl 6)
#  GNUTLS_ALLOW_ID_CHANGE* = (1 shl 7)
#  GNUTLS_ENABLE_FALSE_START* = (1 shl 8)
#  GNUTLS_FORCE_CLIENT_CERT* = (1 shl 9)
#  GNUTLS_NO_TICKETS* = (1 shl 10)
#  GNUTLS_ENABLE_CERT_TYPE_NEG* = 0

##  Here for compatibility reasons
## *
##  gnutls_alert_level_t:
##  @GNUTLS_AL_WARNING: Alert of warning severity.
##  @GNUTLS_AL_FATAL: Alert of fatal severity.
##
##  Enumeration of different TLS alert severities.
##

type
  gnutls_alert_level_t* {.size: sizeof(cint).} = enum
    GNUTLS_AL_WARNING = 1, GNUTLS_AL_FATAL


## *
##  gnutls_alert_description_t:
##  @GNUTLS_A_CLOSE_NOTIFY: Close notify.
##  @GNUTLS_A_UNEXPECTED_MESSAGE: Unexpected message.
##  @GNUTLS_A_BAD_RECORD_MAC: Bad record MAC.
##  @GNUTLS_A_DECRYPTION_FAILED: Decryption failed.
##  @GNUTLS_A_RECORD_OVERFLOW: Record overflow.
##  @GNUTLS_A_DECOMPRESSION_FAILURE: Decompression failed.
##  @GNUTLS_A_HANDSHAKE_FAILURE: Handshake failed.
##  @GNUTLS_A_SSL3_NO_CERTIFICATE: No certificate.
##  @GNUTLS_A_BAD_CERTIFICATE: Certificate is bad.
##  @GNUTLS_A_UNSUPPORTED_CERTIFICATE: Certificate is not supported.
##  @GNUTLS_A_CERTIFICATE_REVOKED: Certificate was revoked.
##  @GNUTLS_A_CERTIFICATE_EXPIRED: Certificate is expired.
##  @GNUTLS_A_CERTIFICATE_UNKNOWN: Unknown certificate.
##  @GNUTLS_A_ILLEGAL_PARAMETER: Illegal parameter.
##  @GNUTLS_A_UNKNOWN_CA: CA is unknown.
##  @GNUTLS_A_ACCESS_DENIED: Access was denied.
##  @GNUTLS_A_DECODE_ERROR: Decode error.
##  @GNUTLS_A_DECRYPT_ERROR: Decrypt error.
##  @GNUTLS_A_EXPORT_RESTRICTION: Export restriction.
##  @GNUTLS_A_PROTOCOL_VERSION: Error in protocol version.
##  @GNUTLS_A_INSUFFICIENT_SECURITY: Insufficient security.
##  @GNUTLS_A_INTERNAL_ERROR: Internal error.
##  @GNUTLS_A_INAPPROPRIATE_FALLBACK: Inappropriate fallback,
##  @GNUTLS_A_USER_CANCELED: User canceled.
##  @GNUTLS_A_NO_RENEGOTIATION: No renegotiation is allowed.
##  @GNUTLS_A_MISSING_EXTENSION: An extension was expected but was not seen
##  @GNUTLS_A_UNSUPPORTED_EXTENSION: An unsupported extension was
##    sent.
##  @GNUTLS_A_CERTIFICATE_UNOBTAINABLE: Could not retrieve the
##    specified certificate.
##  @GNUTLS_A_UNRECOGNIZED_NAME: The server name sent was not
##    recognized.
##  @GNUTLS_A_UNKNOWN_PSK_IDENTITY: The SRP/PSK username is missing
##    or not known.
##  @GNUTLS_A_NO_APPLICATION_PROTOCOL: The ALPN protocol requested is
##    not supported by the peer.
##
##  Enumeration of different TLS alerts.
##

type
  gnutls_alert_description_t* {.size: sizeof(cint).} = enum
    GNUTLS_A_CLOSE_NOTIFY, GNUTLS_A_UNEXPECTED_MESSAGE = 10,
    GNUTLS_A_BAD_RECORD_MAC = 20, GNUTLS_A_DECRYPTION_FAILED,
    GNUTLS_A_RECORD_OVERFLOW, GNUTLS_A_DECOMPRESSION_FAILURE = 30,
    GNUTLS_A_HANDSHAKE_FAILURE = 40, GNUTLS_A_SSL3_NO_CERTIFICATE = 41,
    GNUTLS_A_BAD_CERTIFICATE = 42, GNUTLS_A_UNSUPPORTED_CERTIFICATE,
    GNUTLS_A_CERTIFICATE_REVOKED, GNUTLS_A_CERTIFICATE_EXPIRED,
    GNUTLS_A_CERTIFICATE_UNKNOWN, GNUTLS_A_ILLEGAL_PARAMETER, GNUTLS_A_UNKNOWN_CA,
    GNUTLS_A_ACCESS_DENIED, GNUTLS_A_DECODE_ERROR = 50, GNUTLS_A_DECRYPT_ERROR,
    GNUTLS_A_EXPORT_RESTRICTION = 60, GNUTLS_A_PROTOCOL_VERSION = 70,
    GNUTLS_A_INSUFFICIENT_SECURITY, GNUTLS_A_INTERNAL_ERROR = 80,
    GNUTLS_A_INAPPROPRIATE_FALLBACK = 86, GNUTLS_A_USER_CANCELED = 90,
    GNUTLS_A_NO_RENEGOTIATION = 100, GNUTLS_A_MISSING_EXTENSION = 109,
    GNUTLS_A_UNSUPPORTED_EXTENSION = 110, GNUTLS_A_CERTIFICATE_UNOBTAINABLE = 111,
    GNUTLS_A_UNRECOGNIZED_NAME = 112, GNUTLS_A_UNKNOWN_PSK_IDENTITY = 115,
    GNUTLS_A_NO_APPLICATION_PROTOCOL = 120

const
  GNUTLS_A_MAX = GNUTLS_A_NO_APPLICATION_PROTOCOL

## *
##  gnutls_handshake_description_t:
##  @GNUTLS_HANDSHAKE_HELLO_REQUEST: Hello request.
##  @GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST: DTLS Hello verify request.
##  @GNUTLS_HANDSHAKE_CLIENT_HELLO: Client hello.
##  @GNUTLS_HANDSHAKE_SERVER_HELLO: Server hello.
##  @GNUTLS_HANDSHAKE_END_OF_EARLY_DATA: End of early data.
##  @GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST: Hello retry request.
##  @GNUTLS_HANDSHAKE_NEW_SESSION_TICKET: New session ticket.
##  @GNUTLS_HANDSHAKE_CERTIFICATE_PKT: Certificate packet.
##  @GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE: Server key exchange.
##  @GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST: Certificate request.
##  @GNUTLS_HANDSHAKE_SERVER_HELLO_DONE: Server hello done.
##  @GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY: Certificate verify.
##  @GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: Client key exchange.
##  @GNUTLS_HANDSHAKE_FINISHED: Finished.
##  @GNUTLS_HANDSHAKE_CERTIFICATE_STATUS: Certificate status (OCSP).
##  @GNUTLS_HANDSHAKE_KEY_UPDATE: TLS1.3 key update message.
##  @GNUTLS_HANDSHAKE_SUPPLEMENTAL: Supplemental.
##  @GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC: Change Cipher Spec.
##  @GNUTLS_HANDSHAKE_CLIENT_HELLO_V2: SSLv2 Client Hello.
##  @GNUTLS_HANDSHAKE_ENCRYPTED_EXTENSIONS: Encrypted extensions message.
##
##  Enumeration of different TLS handshake packets.
##

type
  gnutls_handshake_description_t* {.size: sizeof(cint).} = enum
    GNUTLS_HANDSHAKE_HELLO_REQUEST = 0, GNUTLS_HANDSHAKE_CLIENT_HELLO = 1,
    GNUTLS_HANDSHAKE_SERVER_HELLO = 2, GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST = 3,
    GNUTLS_HANDSHAKE_NEW_SESSION_TICKET = 4,
    GNUTLS_HANDSHAKE_END_OF_EARLY_DATA = 5,
    GNUTLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 8,
    GNUTLS_HANDSHAKE_CERTIFICATE_PKT = 11,
    GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    GNUTLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16, GNUTLS_HANDSHAKE_FINISHED = 20,
    GNUTLS_HANDSHAKE_CERTIFICATE_STATUS = 22, GNUTLS_HANDSHAKE_SUPPLEMENTAL = 23,
    GNUTLS_HANDSHAKE_KEY_UPDATE = 24, GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC = 254,
    GNUTLS_HANDSHAKE_CLIENT_HELLO_V2 = 1024,
    GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST = 1025


#const
#  GNUTLS_HANDSHAKE_ANY* = (cast[cuint](-1))

proc gnutls_handshake_description_get_name*(
    `type`: gnutls_handshake_description_t): cstring {.
    importc: "gnutls_handshake_description_get_name", gnutls_import.}
## *
##  gnutls_certificate_status_t:
##  @GNUTLS_CERT_INVALID: The certificate is not signed by one of the
##    known authorities or the signature is invalid (deprecated by the flags
##    %GNUTLS_CERT_SIGNATURE_FAILURE and %GNUTLS_CERT_SIGNER_NOT_FOUND).
##  @GNUTLS_CERT_SIGNATURE_FAILURE: The signature verification failed.
##  @GNUTLS_CERT_REVOKED: Certificate is revoked by its authority.  In X.509 this will be
##    set only if CRLs are checked.
##  @GNUTLS_CERT_SIGNER_NOT_FOUND: The certificate's issuer is not known.
##    This is the case if the issuer is not included in the trusted certificate list.
##  @GNUTLS_CERT_SIGNER_NOT_CA: The certificate's signer was not a CA. This
##    may happen if this was a version 1 certificate, which is common with
##    some CAs, or a version 3 certificate without the basic constrains extension.
##  @GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE: The certificate's signer constraints were
##    violated.
##  @GNUTLS_CERT_INSECURE_ALGORITHM:  The certificate was signed using an insecure
##    algorithm such as MD2 or MD5. These algorithms have been broken and
##    should not be trusted.
##  @GNUTLS_CERT_NOT_ACTIVATED: The certificate is not yet activated.
##  @GNUTLS_CERT_EXPIRED: The certificate has expired.
##  @GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED: The revocation data are old and have been superseded.
##  @GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE: The revocation data have a future issue date.
##  @GNUTLS_CERT_UNEXPECTED_OWNER: The owner is not the expected one.
##  @GNUTLS_CERT_MISMATCH: The certificate presented isn't the expected one (TOFU)
##  @GNUTLS_CERT_PURPOSE_MISMATCH: The certificate or an intermediate does not match the intended purpose (extended key usage).
##  @GNUTLS_CERT_MISSING_OCSP_STATUS: The certificate requires the server to send the certifiate status, but no status was received.
##  @GNUTLS_CERT_INVALID_OCSP_STATUS: The received OCSP status response is invalid.
##  @GNUTLS_CERT_UNKNOWN_CRIT_EXTENSIONS: The certificate has extensions marked as critical which are not supported.
##
##  Enumeration of certificate status codes.  Note that the status
##  bits may have different meanings in OpenPGP keys and X.509
##  certificate verification.
##

type
  gnutls_certificate_status_t* {.size: sizeof(cint).} = enum
    GNUTLS_CERT_INVALID = 1 shl 1, GNUTLS_CERT_REVOKED = 1 shl 5,
    GNUTLS_CERT_SIGNER_NOT_FOUND = 1 shl 6, GNUTLS_CERT_SIGNER_NOT_CA = 1 shl 7,
    GNUTLS_CERT_INSECURE_ALGORITHM = 1 shl 8, GNUTLS_CERT_NOT_ACTIVATED = 1 shl 9,
    GNUTLS_CERT_EXPIRED = 1 shl 10, GNUTLS_CERT_SIGNATURE_FAILURE = 1 shl 11,
    GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED = 1 shl 12,
    GNUTLS_CERT_UNEXPECTED_OWNER = 1 shl 14,
    GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE = 1 shl 15,
    GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE = 1 shl 16,
    GNUTLS_CERT_MISMATCH = 1 shl 17, GNUTLS_CERT_PURPOSE_MISMATCH = 1 shl 18,
    GNUTLS_CERT_MISSING_OCSP_STATUS = 1 shl 19,
    GNUTLS_CERT_INVALID_OCSP_STATUS = 1 shl 20,
    GNUTLS_CERT_UNKNOWN_CRIT_EXTENSIONS = 1 shl 21


## *
##  gnutls_certificate_request_t:
##  @GNUTLS_CERT_IGNORE: Ignore certificate.
##  @GNUTLS_CERT_REQUEST: Request certificate.
##  @GNUTLS_CERT_REQUIRE: Require certificate.
##
##  Enumeration of certificate request types.
##

type
  gnutls_certificate_request_t* {.size: sizeof(cint).} = enum
    GNUTLS_CERT_IGNORE = 0, GNUTLS_CERT_REQUEST = 1, GNUTLS_CERT_REQUIRE = 2


## *
##  gnutls_openpgp_crt_status_t:
##  @GNUTLS_OPENPGP_CERT: Send entire certificate.
##  @GNUTLS_OPENPGP_CERT_FINGERPRINT: Send only certificate fingerprint.
##
##  Enumeration of ways to send OpenPGP certificate.
##

type
  gnutls_openpgp_crt_status_t* {.size: sizeof(cint).} = enum
    GNUTLS_OPENPGP_CERT = 0, GNUTLS_OPENPGP_CERT_FINGERPRINT = 1


## *
##  gnutls_close_request_t:
##  @GNUTLS_SHUT_RDWR: Disallow further receives/sends.
##  @GNUTLS_SHUT_WR: Disallow further sends.
##
##  Enumeration of how TLS session should be terminated.  See gnutls_bye().
##

type
  gnutls_close_request_t* {.size: sizeof(cint).} = enum
    GNUTLS_SHUT_RDWR = 0, GNUTLS_SHUT_WR = 1


## *
##  gnutls_protocol_t:
##  @GNUTLS_SSL3: SSL version 3.0.
##  @GNUTLS_TLS1_0: TLS version 1.0.
##  @GNUTLS_TLS1: Same as %GNUTLS_TLS1_0.
##  @GNUTLS_TLS1_1: TLS version 1.1.
##  @GNUTLS_TLS1_2: TLS version 1.2.
##  @GNUTLS_TLS1_3: TLS version 1.3.
##  @GNUTLS_DTLS1_0: DTLS version 1.0.
##  @GNUTLS_DTLS1_2: DTLS version 1.2.
##  @GNUTLS_DTLS0_9: DTLS version 0.9 (Cisco AnyConnect / OpenSSL 0.9.8e).
##  @GNUTLS_TLS_VERSION_MAX: Maps to the highest supported TLS version.
##  @GNUTLS_DTLS_VERSION_MAX: Maps to the highest supported DTLS version.
##  @GNUTLS_VERSION_UNKNOWN: Unknown SSL/TLS version.
##
##  Enumeration of different SSL/TLS protocol versions.
##

type
  gnutls_protocol_t* {.size: sizeof(cint).} = enum
    GNUTLS_SSL3 = 1, GNUTLS_TLS1_0 = 2, GNUTLS_TLS1_1 = 3, GNUTLS_TLS1_2 = 4,
    GNUTLS_TLS1_3 = 5, GNUTLS_DTLS0_9 = 200, GNUTLS_DTLS1_0 = 201, ##  201
    GNUTLS_DTLS1_2 = 202, GNUTLS_VERSION_UNKNOWN = 0x000000FF

const
  GNUTLS_TLS1 = GNUTLS_TLS1_0
  GNUTLS_DTLS_VERSION_MIN = GNUTLS_DTLS0_9
  GNUTLS_DTLS_VERSION_MAX = GNUTLS_DTLS1_2
  GNUTLS_TLS_VERSION_MAX = GNUTLS_TLS1_3

## *
##  gnutls_certificate_type_t:
##  @GNUTLS_CRT_UNKNOWN: Unknown certificate type.
##  @GNUTLS_CRT_X509: X.509 Certificate.
##  @GNUTLS_CRT_OPENPGP: OpenPGP certificate.
##  @GNUTLS_CRT_RAWPK: Raw public-key (SubjectPublicKeyInfo)
##
##  Enumeration of different certificate types.
##

type
  gnutls_certificate_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_CRT_UNKNOWN = 0, GNUTLS_CRT_X509 = 1, GNUTLS_CRT_OPENPGP = 2,
    GNUTLS_CRT_RAWPK = 3

const
  GNUTLS_CRT_MAX = GNUTLS_CRT_RAWPK

## *
##  gnutls_x509_crt_fmt_t:
##  @GNUTLS_X509_FMT_DER: X.509 certificate in DER format (binary).
##  @GNUTLS_X509_FMT_PEM: X.509 certificate in PEM format (text).
##
##  Enumeration of different certificate encoding formats.
##

type
  gnutls_x509_crt_fmt_t* {.size: sizeof(cint).} = enum
    GNUTLS_X509_FMT_DER = 0, GNUTLS_X509_FMT_PEM = 1


## *
##  gnutls_certificate_print_formats_t:
##  @GNUTLS_CRT_PRINT_FULL: Full information about certificate.
##  @GNUTLS_CRT_PRINT_FULL_NUMBERS: Full information about certificate and include easy to parse public key parameters.
##  @GNUTLS_CRT_PRINT_COMPACT: Information about certificate name in one line, plus identification of the public key.
##  @GNUTLS_CRT_PRINT_ONELINE: Information about certificate in one line.
##  @GNUTLS_CRT_PRINT_UNSIGNED_FULL: All info for an unsigned certificate.
##
##  Enumeration of different certificate printing variants.
##

type
  gnutls_certificate_print_formats_t* {.size: sizeof(cint).} = enum
    GNUTLS_CRT_PRINT_FULL = 0, GNUTLS_CRT_PRINT_ONELINE = 1,
    GNUTLS_CRT_PRINT_UNSIGNED_FULL = 2, GNUTLS_CRT_PRINT_COMPACT = 3,
    GNUTLS_CRT_PRINT_FULL_NUMBERS = 4


type
  gnutls_pk_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_PK_UNKNOWN = 0, GNUTLS_PK_RSA = 1, GNUTLS_PK_DSA = 2, GNUTLS_PK_DH = 3,
    GNUTLS_PK_ECDSA = 4, GNUTLS_PK_ECDH_X25519 = 5, GNUTLS_PK_RSA_PSS = 6,
    GNUTLS_PK_EDDSA_ED25519 = 7, GNUTLS_PK_GOST_01 = 8, GNUTLS_PK_GOST_12_256 = 9,
    GNUTLS_PK_GOST_12_512 = 10

const
  GNUTLS_PK_ECC* = GNUTLS_PK_ECDSA
  GNUTLS_PK_EC* = GNUTLS_PK_ECDSA
  GNUTLS_PK_ECDHX* = GNUTLS_PK_ECDH_X25519

## *
##  gnutls_pk_algorithm_t:
##  @GNUTLS_PK_UNKNOWN: Unknown public-key algorithm.
##  @GNUTLS_PK_RSA: RSA public-key algorithm.
##  @GNUTLS_PK_RSA_PSS: RSA public-key algorithm, with PSS padding.
##  @GNUTLS_PK_DSA: DSA public-key algorithm.
##  @GNUTLS_PK_DH: Diffie-Hellman algorithm. Used to generate parameters.
##  @GNUTLS_PK_ECDSA: Elliptic curve algorithm. These parameters are compatible with the ECDSA and ECDH algorithm.
##  @GNUTLS_PK_ECDH_X25519: Elliptic curve algorithm, restricted to ECDH as per rfc7748.
##  @GNUTLS_PK_EDDSA_ED25519: Edwards curve Digital signature algorithm. Used with SHA512 on signatures.
##  @GNUTLS_PK_GOST_01: GOST R 34.10-2001 algorithm per rfc5832.
##  @GNUTLS_PK_GOST_12_256: GOST R 34.10-2012 algorithm, 256-bit key per rfc7091.
##  @GNUTLS_PK_GOST_12_512: GOST R 34.10-2012 algorithm, 512-bit key per rfc7091.
##
##  Enumeration of different public-key algorithms.
##


const
  GNUTLS_PK_MAX = GNUTLS_PK_GOST_12_512

proc gnutls_pk_algorithm_get_name*(algorithm: gnutls_pk_algorithm_t): cstring {.
    importc: "gnutls_pk_algorithm_get_name", gnutls_import.}
## *
##  gnutls_sign_algorithm_t:
##  @GNUTLS_SIGN_UNKNOWN: Unknown signature algorithm.
##  @GNUTLS_SIGN_RSA_RAW: Digital signature algorithm RSA with DigestInfo formatted data
##  @GNUTLS_SIGN_RSA_SHA1: Digital signature algorithm RSA with SHA-1
##  @GNUTLS_SIGN_RSA_SHA: Same as %GNUTLS_SIGN_RSA_SHA1.
##  @GNUTLS_SIGN_DSA_SHA1: Digital signature algorithm DSA with SHA-1
##  @GNUTLS_SIGN_DSA_SHA224: Digital signature algorithm DSA with SHA-224
##  @GNUTLS_SIGN_DSA_SHA256: Digital signature algorithm DSA with SHA-256
##  @GNUTLS_SIGN_DSA_SHA384: Digital signature algorithm DSA with SHA-384
##  @GNUTLS_SIGN_DSA_SHA512: Digital signature algorithm DSA with SHA-512
##  @GNUTLS_SIGN_DSA_SHA: Same as %GNUTLS_SIGN_DSA_SHA1.
##  @GNUTLS_SIGN_RSA_MD5: Digital signature algorithm RSA with MD5.
##  @GNUTLS_SIGN_RSA_MD2: Digital signature algorithm RSA with MD2.
##  @GNUTLS_SIGN_RSA_RMD160: Digital signature algorithm RSA with RMD-160.
##  @GNUTLS_SIGN_RSA_SHA256: Digital signature algorithm RSA with SHA-256.
##  @GNUTLS_SIGN_RSA_SHA384: Digital signature algorithm RSA with SHA-384.
##  @GNUTLS_SIGN_RSA_SHA512: Digital signature algorithm RSA with SHA-512.
##  @GNUTLS_SIGN_RSA_SHA224: Digital signature algorithm RSA with SHA-224.
##  @GNUTLS_SIGN_ECDSA_SHA1: ECDSA with SHA1.
##  @GNUTLS_SIGN_ECDSA_SHA224: Digital signature algorithm ECDSA with SHA-224.
##  @GNUTLS_SIGN_ECDSA_SHA256: Digital signature algorithm ECDSA with SHA-256.
##  @GNUTLS_SIGN_ECDSA_SHA384: Digital signature algorithm ECDSA with SHA-384.
##  @GNUTLS_SIGN_ECDSA_SHA512: Digital signature algorithm ECDSA with SHA-512.
##  @GNUTLS_SIGN_ECDSA_SECP256R1_SHA256: Digital signature algorithm ECDSA-SECP256R1 with SHA-256 (used in TLS 1.3 but not PKIX).
##  @GNUTLS_SIGN_ECDSA_SECP384R1_SHA384: Digital signature algorithm ECDSA-SECP384R1 with SHA-384 (used in TLS 1.3 but not PKIX).
##  @GNUTLS_SIGN_ECDSA_SECP521R1_SHA512: Digital signature algorithm ECDSA-SECP521R1 with SHA-512 (used in TLS 1.3 but not PKIX).
##  @GNUTLS_SIGN_ECDSA_SHA3_224: Digital signature algorithm ECDSA with SHA3-224.
##  @GNUTLS_SIGN_ECDSA_SHA3_256: Digital signature algorithm ECDSA with SHA3-256.
##  @GNUTLS_SIGN_ECDSA_SHA3_384: Digital signature algorithm ECDSA with SHA3-384.
##  @GNUTLS_SIGN_ECDSA_SHA3_512: Digital signature algorithm ECDSA with SHA3-512.
##  @GNUTLS_SIGN_DSA_SHA3_224: Digital signature algorithm DSA with SHA3-224.
##  @GNUTLS_SIGN_DSA_SHA3_256: Digital signature algorithm DSA with SHA3-256.
##  @GNUTLS_SIGN_DSA_SHA3_384: Digital signature algorithm DSA with SHA3-384.
##  @GNUTLS_SIGN_DSA_SHA3_512: Digital signature algorithm DSA with SHA3-512.
##  @GNUTLS_SIGN_RSA_SHA3_224: Digital signature algorithm RSA with SHA3-224.
##  @GNUTLS_SIGN_RSA_SHA3_256: Digital signature algorithm RSA with SHA3-256.
##  @GNUTLS_SIGN_RSA_SHA3_384: Digital signature algorithm RSA with SHA3-384.
##  @GNUTLS_SIGN_RSA_SHA3_512: Digital signature algorithm RSA with SHA3-512.
##  @GNUTLS_SIGN_RSA_PSS_RSAE_SHA256: Digital signature algorithm RSA with SHA-256,
##       with PSS padding (RSA PKCS#1 1.5 certificate). This signature is identical
##       to #GNUTLS_SIGN_RSA_PSS_SHA256, but they are distinct as the TLS1.3 protocol
##       treats them differently.
##  @GNUTLS_SIGN_RSA_PSS_RSAE_SHA384: Digital signature algorithm RSA with SHA-384,
##       with PSS padding (RSA PKCS#1 1.5 certificate). This signature is identical
##       to #GNUTLS_SIGN_RSA_PSS_SHA384, but they are distinct as the TLS1.3 protocol
##       treats them differently.
##  @GNUTLS_SIGN_RSA_PSS_RSAE_SHA512: Digital signature algorithm RSA with SHA-512,
##       with PSS padding (RSA PKCS#1 1.5 certificate). This signature is identical
##       to #GNUTLS_SIGN_RSA_PSS_SHA512, but they are distinct as the TLS1.3 protocol
##       treats them differently.
##  @GNUTLS_SIGN_RSA_PSS_SHA256: Digital signature algorithm RSA with SHA-256, with PSS padding (RSA-PSS certificate).
##  @GNUTLS_SIGN_RSA_PSS_SHA384: Digital signature algorithm RSA with SHA-384, with PSS padding (RSA-PSS certificate).
##  @GNUTLS_SIGN_RSA_PSS_SHA512: Digital signature algorithm RSA with SHA-512, with PSS padding (RSA-PSS certificate).
##  @GNUTLS_SIGN_EDDSA_ED25519: Digital signature algorithm EdDSA with Ed25519 curve.
##  @GNUTLS_SIGN_GOST_94: Digital signature algorithm GOST R 34.10-2001 with GOST R 34.11-94
##  @GNUTLS_SIGN_GOST_256: Digital signature algorithm GOST R 34.10-2012 with GOST R 34.11-2012 256 bit
##  @GNUTLS_SIGN_GOST_512: Digital signature algorithm GOST R 34.10-2012 with GOST R 34.11-2012 512 bit
##
##  Enumeration of different digital signature algorithms.
##

type
  gnutls_sign_algorithm_t* {.size: sizeof(cint).} = enum
    GNUTLS_SIGN_UNKNOWN = 0, GNUTLS_SIGN_RSA_SHA1 = 1, GNUTLS_SIGN_DSA_SHA1 = 2,
    GNUTLS_SIGN_RSA_MD5 = 3, GNUTLS_SIGN_RSA_MD2 = 4, GNUTLS_SIGN_RSA_RMD160 = 5,
    GNUTLS_SIGN_RSA_SHA256 = 6, GNUTLS_SIGN_RSA_SHA384 = 7,
    GNUTLS_SIGN_RSA_SHA512 = 8, GNUTLS_SIGN_RSA_SHA224 = 9,
    GNUTLS_SIGN_DSA_SHA224 = 10, GNUTLS_SIGN_DSA_SHA256 = 11,
    GNUTLS_SIGN_ECDSA_SHA1 = 12, GNUTLS_SIGN_ECDSA_SHA224 = 13,
    GNUTLS_SIGN_ECDSA_SHA256 = 14, GNUTLS_SIGN_ECDSA_SHA384 = 15,
    GNUTLS_SIGN_ECDSA_SHA512 = 16, GNUTLS_SIGN_DSA_SHA384 = 17,
    GNUTLS_SIGN_DSA_SHA512 = 18, GNUTLS_SIGN_ECDSA_SHA3_224 = 20,
    GNUTLS_SIGN_ECDSA_SHA3_256 = 21, GNUTLS_SIGN_ECDSA_SHA3_384 = 22,
    GNUTLS_SIGN_ECDSA_SHA3_512 = 23, GNUTLS_SIGN_DSA_SHA3_224 = 24,
    GNUTLS_SIGN_DSA_SHA3_256 = 25, GNUTLS_SIGN_DSA_SHA3_384 = 26,
    GNUTLS_SIGN_DSA_SHA3_512 = 27, GNUTLS_SIGN_RSA_SHA3_224 = 28,
    GNUTLS_SIGN_RSA_SHA3_256 = 29, GNUTLS_SIGN_RSA_SHA3_384 = 30,
    GNUTLS_SIGN_RSA_SHA3_512 = 31, GNUTLS_SIGN_RSA_PSS_SHA256 = 32,
    GNUTLS_SIGN_RSA_PSS_SHA384 = 33, GNUTLS_SIGN_RSA_PSS_SHA512 = 34,
    GNUTLS_SIGN_EDDSA_ED25519 = 35, GNUTLS_SIGN_RSA_RAW = 36,
    GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 = 37,
    GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 = 38,
    GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 = 39, GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 = 40,
    GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 = 41, GNUTLS_SIGN_RSA_PSS_RSAE_SHA512 = 42,
    GNUTLS_SIGN_GOST_94 = 43, GNUTLS_SIGN_GOST_256 = 44, GNUTLS_SIGN_GOST_512 = 45

const
  GNUTLS_SIGN_RSA_SHA = GNUTLS_SIGN_RSA_SHA1
  GNUTLS_SIGN_DSA_SHA = GNUTLS_SIGN_DSA_SHA1
  GNUTLS_SIGN_MAX = GNUTLS_SIGN_GOST_512

## *
##  gnutls_ecc_curve_t:
##  @GNUTLS_ECC_CURVE_INVALID: Cannot be known
##  @GNUTLS_ECC_CURVE_SECP192R1: the SECP192R1 curve
##  @GNUTLS_ECC_CURVE_SECP224R1: the SECP224R1 curve
##  @GNUTLS_ECC_CURVE_SECP256R1: the SECP256R1 curve
##  @GNUTLS_ECC_CURVE_SECP384R1: the SECP384R1 curve
##  @GNUTLS_ECC_CURVE_SECP521R1: the SECP521R1 curve
##  @GNUTLS_ECC_CURVE_X25519: the X25519 curve (ECDH only)
##  @GNUTLS_ECC_CURVE_ED25519: the Ed25519 curve
##  @GNUTLS_ECC_CURVE_GOST256CPA: GOST R 34.10 CryptoPro 256 A curve
##  @GNUTLS_ECC_CURVE_GOST256CPB: GOST R 34.10 CryptoPro 256 B curve
##  @GNUTLS_ECC_CURVE_GOST256CPC: GOST R 34.10 CryptoPro 256 C curve
##  @GNUTLS_ECC_CURVE_GOST256CPXA: GOST R 34.10 CryptoPro 256 XchA curve
##  @GNUTLS_ECC_CURVE_GOST256CPXB: GOST R 34.10 CryptoPro 256 XchB curve
##  @GNUTLS_ECC_CURVE_GOST512A: GOST R 34.10 TC26 512 A curve
##  @GNUTLS_ECC_CURVE_GOST512B: GOST R 34.10 TC26 512 B curve
##
##  Enumeration of ECC curves.
##

type
  gnutls_ecc_curve_t* {.size: sizeof(cint).} = enum
    GNUTLS_ECC_CURVE_INVALID = 0, GNUTLS_ECC_CURVE_SECP224R1,
    GNUTLS_ECC_CURVE_SECP256R1, GNUTLS_ECC_CURVE_SECP384R1,
    GNUTLS_ECC_CURVE_SECP521R1, GNUTLS_ECC_CURVE_SECP192R1,
    GNUTLS_ECC_CURVE_X25519, GNUTLS_ECC_CURVE_ED25519,
    GNUTLS_ECC_CURVE_GOST256CPA, GNUTLS_ECC_CURVE_GOST256CPB,
    GNUTLS_ECC_CURVE_GOST256CPC, GNUTLS_ECC_CURVE_GOST256CPXA,
    GNUTLS_ECC_CURVE_GOST256CPXB, GNUTLS_ECC_CURVE_GOST512A,
    GNUTLS_ECC_CURVE_GOST512B

const
  GNUTLS_ECC_CURVE_MAX = GNUTLS_ECC_CURVE_GOST512B

## *
##  gnutls_group_t:
##  @GNUTLS_GROUP_INVALID: Indicates unknown/invalid group
##  @GNUTLS_GROUP_SECP192R1: the SECP192R1 curve group (legacy, only for TLS 1.2 compatibility)
##  @GNUTLS_GROUP_SECP224R1: the SECP224R1 curve group (legacy, only for TLS 1.2 compatibility)
##  @GNUTLS_GROUP_SECP256R1: the SECP256R1 curve group
##  @GNUTLS_GROUP_SECP384R1: the SECP384R1 curve group
##  @GNUTLS_GROUP_SECP521R1: the SECP521R1 curve group
##  @GNUTLS_GROUP_X25519: the X25519 curve group
##  @GNUTLS_GROUP_FFDHE2048: the FFDHE2048 group
##  @GNUTLS_GROUP_FFDHE3072: the FFDHE3072 group
##  @GNUTLS_GROUP_FFDHE4096: the FFDHE4096 group
##  @GNUTLS_GROUP_FFDHE6144: the FFDHE6144 group
##  @GNUTLS_GROUP_FFDHE8192: the FFDHE8192 group
##
##  Enumeration of supported groups. It is intended to be backwards
##  compatible with the enumerations in %gnutls_ecc_curve_t for the groups
##  which are valid elliptic curves.
##

type
  gnutls_group_t* {.size: sizeof(cint).} = enum
    GNUTLS_GROUP_INVALID = 0,
    GNUTLS_GROUP_SECP224R1 = GNUTLS_ECC_CURVE_SECP224R1,
    GNUTLS_GROUP_SECP256R1 = GNUTLS_ECC_CURVE_SECP256R1,
    GNUTLS_GROUP_SECP384R1 = GNUTLS_ECC_CURVE_SECP384R1,
    GNUTLS_GROUP_SECP521R1 = GNUTLS_ECC_CURVE_SECP521R1,
    GNUTLS_GROUP_SECP192R1 = GNUTLS_ECC_CURVE_SECP192R1,
    GNUTLS_GROUP_X25519 = GNUTLS_ECC_CURVE_X25519, GNUTLS_GROUP_FFDHE2048 = 256,
    GNUTLS_GROUP_FFDHE3072, GNUTLS_GROUP_FFDHE4096, GNUTLS_GROUP_FFDHE8192,
    GNUTLS_GROUP_FFDHE6144

const
  GNUTLS_GROUP_MAX = GNUTLS_GROUP_FFDHE6144

##  macros to allow specifying a specific curve in gnutls_privkey_generate()
##  and gnutls_x509_privkey_generate()

template GNUTLS_CURVE_TO_BITS*(curve: untyped): untyped =
  cast[cuint](((cast[cuint](1) shl 31) or (cast[cuint]((curve)))))

template GNUTLS_BITS_TO_CURVE*(bits: untyped): untyped =
  ((cast[cuint]((bits))) and 0x7FFFFFFF)

template GNUTLS_BITS_ARE_CURVE*(bits: untyped): untyped =
  ((cast[cuint]((bits))) and 0x80000000)

## *
##  gnutls_sec_param_t:
##  @GNUTLS_SEC_PARAM_UNKNOWN: Cannot be known
##  @GNUTLS_SEC_PARAM_INSECURE: Less than 42 bits of security
##  @GNUTLS_SEC_PARAM_EXPORT: 42 bits of security
##  @GNUTLS_SEC_PARAM_VERY_WEAK: 64 bits of security
##  @GNUTLS_SEC_PARAM_WEAK: 72 bits of security
##  @GNUTLS_SEC_PARAM_LOW: 80 bits of security
##  @GNUTLS_SEC_PARAM_LEGACY: 96 bits of security
##  @GNUTLS_SEC_PARAM_MEDIUM: 112 bits of security (used to be %GNUTLS_SEC_PARAM_NORMAL)
##  @GNUTLS_SEC_PARAM_HIGH: 128 bits of security
##  @GNUTLS_SEC_PARAM_ULTRA: 192 bits of security
##  @GNUTLS_SEC_PARAM_FUTURE: 256 bits of security
##
##  Enumeration of security parameters for passive attacks.
##

type
  gnutls_sec_param_t* {.size: sizeof(cint).} = enum
    GNUTLS_SEC_PARAM_UNKNOWN = 0, GNUTLS_SEC_PARAM_INSECURE = 5,
    GNUTLS_SEC_PARAM_EXPORT = 10, GNUTLS_SEC_PARAM_VERY_WEAK = 15,
    GNUTLS_SEC_PARAM_WEAK = 20, GNUTLS_SEC_PARAM_LOW = 25,
    GNUTLS_SEC_PARAM_LEGACY = 30, GNUTLS_SEC_PARAM_MEDIUM = 35,
    GNUTLS_SEC_PARAM_HIGH = 40, GNUTLS_SEC_PARAM_ULTRA = 45,
    GNUTLS_SEC_PARAM_FUTURE = 50

const
  GNUTLS_SEC_PARAM_MAX = GNUTLS_SEC_PARAM_FUTURE

##  old name

const
  GNUTLS_SEC_PARAM_NORMAL* = GNUTLS_SEC_PARAM_MEDIUM

## *
##  gnutls_channel_binding_t:
##  @GNUTLS_CB_TLS_UNIQUE: "tls-unique" (RFC 5929) channel binding
##
##  Enumeration of support channel binding types.
##

type
  gnutls_channel_binding_t* {.size: sizeof(cint).} = enum
    GNUTLS_CB_TLS_UNIQUE


## *
##  gnutls_gost_paramset_t:
##  @GNUTLS_GOST_PARAMSET_UNKNOWN: Unknown/default parameter set
##  @GNUTLS_GOST_PARAMSET_TC26_Z: Specified by TC26, see rfc7836
##  @GNUTLS_GOST_PARAMSET_CP_A: CryptoPro-A, see rfc4357
##  @GNUTLS_GOST_PARAMSET_CP_B: CryptoPro-B, see rfc4357
##  @GNUTLS_GOST_PARAMSET_CP_C: CryptoPro-C, see rfc4357
##  @GNUTLS_GOST_PARAMSET_CP_D: CryptoPro-D, see rfc4357
##
##  Enumeration of different GOST 28147 parameter sets.
##

type
  gnutls_gost_paramset_t* {.size: sizeof(cint).} = enum
    GNUTLS_GOST_PARAMSET_UNKNOWN = 0, GNUTLS_GOST_PARAMSET_TC26_Z,
    GNUTLS_GOST_PARAMSET_CP_A, GNUTLS_GOST_PARAMSET_CP_B,
    GNUTLS_GOST_PARAMSET_CP_C, GNUTLS_GOST_PARAMSET_CP_D


## *
##  gnutls_ctype_target_t:
##  @GNUTLS_CTYPE_CLIENT: for requesting client certificate type values.
##  @GNUTLS_CTYPE_SERVER: for requesting server certificate type values.
##  @GNUTLS_CTYPE_OURS: for requesting our certificate type values.
##  @GNUTLS_CTYPE_PEERS: for requesting the peers' certificate type values.
##
##  Enumeration of certificate type targets with respect to asymmetric
##  certificate types as specified in RFC7250 and P2P connection set up
##  as specified in draft-vanrein-tls-symmetry-02.
##

type
  gnutls_ctype_target_t* {.size: sizeof(cint).} = enum
    GNUTLS_CTYPE_CLIENT, GNUTLS_CTYPE_SERVER, GNUTLS_CTYPE_OURS, GNUTLS_CTYPE_PEERS


##  If you want to change this, then also change the define in
##  gnutls_int.h, and recompile.
##

type
  gnutls_transport_ptr_t* = pointer
  gnutls_session_int* {.bycopy.} = object

  gnutls_session_t* = ptr gnutls_session_int
  gnutls_dh_params_int* {.bycopy.} = object

  gnutls_dh_params_t* = ptr gnutls_dh_params_int

##  XXX ugly.

type
  gnutls_x509_privkey_int* {.bycopy.} = object
  gnutls_rsa_params_t* = ptr gnutls_x509_privkey_int
  gnutls_priority_st* {.bycopy.} = object

  params_gnutls_1142* {.bycopy.} = object {.union.}
    dh*: gnutls_dh_params_t
    rsa_export*: gnutls_rsa_params_t

  gnutls_priority_t* = ptr gnutls_priority_st
  gnutls_datum_t* {.bycopy.} = object
    data*: ptr cuchar
    size*: csize

  gnutls_params_st* {.bycopy.} = object
    `type`*: gnutls_params_type_t
    params*: params_gnutls_1142
    deinit*: cint

  gnutls_params_function* = proc (a1: gnutls_session_t; a2: gnutls_params_type_t;
                               a3: ptr gnutls_params_st): cint

##  internal functions

proc gnutls_init*(session: ptr gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_init", gnutls_import.}
proc gnutls_deinit*(session: gnutls_session_t) {.importc: "gnutls_deinit",
    gnutls_import.}
template gnutls_deinit*(x: untyped): untyped =
  gnutls_deinit(x)

proc gnutls_bye*(session: gnutls_session_t; how: gnutls_close_request_t): cint {.
    importc: "gnutls_bye", gnutls_import.}
proc gnutls_handshake*(session: gnutls_session_t): cint {.
    importc: "gnutls_handshake", gnutls_import.}
proc gnutls_reauth*(session: gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_reauth", gnutls_import.}
#const
#  GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT* = (cast[cuint](-1))
#  GNUTLS_INDEFINITE_TIMEOUT* = (cast[cuint](-2))

proc gnutls_handshake_set_timeout*(session: gnutls_session_t; ms: cuint) {.
    importc: "gnutls_handshake_set_timeout", gnutls_import.}
proc gnutls_rehandshake*(session: gnutls_session_t): cint {.
    importc: "gnutls_rehandshake", gnutls_import.}
const
  GNUTLS_KU_PEER* = 1

proc gnutls_session_key_update*(session: gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_session_key_update", gnutls_import.}
proc gnutls_alert_get*(session: gnutls_session_t): gnutls_alert_description_t {.
    importc: "gnutls_alert_get", gnutls_import.}
proc gnutls_alert_send*(session: gnutls_session_t; level: gnutls_alert_level_t;
                       desc: gnutls_alert_description_t): cint {.
    importc: "gnutls_alert_send", gnutls_import.}
proc gnutls_alert_send_appropriate*(session: gnutls_session_t; err: cint): cint {.
    importc: "gnutls_alert_send_appropriate", gnutls_import.}
proc gnutls_alert_get_name*(alert: gnutls_alert_description_t): cstring {.
    importc: "gnutls_alert_get_name", gnutls_import.}
proc gnutls_alert_get_strname*(alert: gnutls_alert_description_t): cstring {.
    importc: "gnutls_alert_get_strname", gnutls_import.}
proc gnutls_pk_bits_to_sec_param*(algo: gnutls_pk_algorithm_t; bits: cuint): gnutls_sec_param_t {.
    importc: "gnutls_pk_bits_to_sec_param", gnutls_import.}
proc gnutls_sec_param_get_name*(param: gnutls_sec_param_t): cstring {.
    importc: "gnutls_sec_param_get_name", gnutls_import.}
proc gnutls_sec_param_to_pk_bits*(algo: gnutls_pk_algorithm_t;
                                 param: gnutls_sec_param_t): cuint {.
    importc: "gnutls_sec_param_to_pk_bits", gnutls_import.}
proc gnutls_sec_param_to_symmetric_bits*(param: gnutls_sec_param_t): cuint {.
    importc: "gnutls_sec_param_to_symmetric_bits", gnutls_import.}
##  Elliptic curves

proc gnutls_ecc_curve_get_name*(curve: gnutls_ecc_curve_t): cstring {.
    importc: "gnutls_ecc_curve_get_name", gnutls_import.}
proc gnutls_ecc_curve_get_oid*(curve: gnutls_ecc_curve_t): cstring {.
    importc: "gnutls_ecc_curve_get_oid", gnutls_import.}
proc gnutls_group_get_name*(group: gnutls_group_t): cstring {.
    importc: "gnutls_group_get_name", gnutls_import.}
proc gnutls_ecc_curve_get_size*(curve: gnutls_ecc_curve_t): cint {.
    importc: "gnutls_ecc_curve_get_size", gnutls_import.}
proc gnutls_ecc_curve_get*(session: gnutls_session_t): gnutls_ecc_curve_t {.
    importc: "gnutls_ecc_curve_get", gnutls_import.}
proc gnutls_group_get*(session: gnutls_session_t): gnutls_group_t {.
    importc: "gnutls_group_get", gnutls_import.}
##  get information on the current session

proc gnutls_cipher_get*(session: gnutls_session_t): gnutls_cipher_algorithm_t {.
    importc: "gnutls_cipher_get", gnutls_import.}
proc gnutls_kx_get*(session: gnutls_session_t): gnutls_kx_algorithm_t {.
    importc: "gnutls_kx_get", gnutls_import.}
proc gnutls_mac_get*(session: gnutls_session_t): gnutls_mac_algorithm_t {.
    importc: "gnutls_mac_get", gnutls_import.}
proc gnutls_certificate_type_get*(session: gnutls_session_t): gnutls_certificate_type_t {.
    importc: "gnutls_certificate_type_get", gnutls_import.}
proc gnutls_certificate_type_get2*(session: gnutls_session_t;
                                  target: gnutls_ctype_target_t): gnutls_certificate_type_t {.
    importc: "gnutls_certificate_type_get2", gnutls_import.}
proc gnutls_sign_algorithm_get*(session: gnutls_session_t): cint {.
    importc: "gnutls_sign_algorithm_get", gnutls_import.}
proc gnutls_sign_algorithm_get_client*(session: gnutls_session_t): cint {.
    importc: "gnutls_sign_algorithm_get_client", gnutls_import.}
proc gnutls_sign_algorithm_get_requested*(session: gnutls_session_t; indx: csize;
    algo: ptr gnutls_sign_algorithm_t): cint {.
    importc: "gnutls_sign_algorithm_get_requested", gnutls_import.}
##  the name of the specified algorithms

proc gnutls_cipher_get_name*(algorithm: gnutls_cipher_algorithm_t): cstring {.
    importc: "gnutls_cipher_get_name", gnutls_import.}
proc gnutls_mac_get_name*(algorithm: gnutls_mac_algorithm_t): cstring {.
    importc: "gnutls_mac_get_name", gnutls_import.}
proc gnutls_digest_get_name*(algorithm: gnutls_digest_algorithm_t): cstring {.
    importc: "gnutls_digest_get_name", gnutls_import.}
proc gnutls_digest_get_oid*(algorithm: gnutls_digest_algorithm_t): cstring {.
    importc: "gnutls_digest_get_oid", gnutls_import.}
proc gnutls_kx_get_name*(algorithm: gnutls_kx_algorithm_t): cstring {.
    importc: "gnutls_kx_get_name", gnutls_import.}
proc gnutls_certificate_type_get_name*(`type`: gnutls_certificate_type_t): cstring {.
    importc: "gnutls_certificate_type_get_name", gnutls_import.}
proc gnutls_pk_get_name*(algorithm: gnutls_pk_algorithm_t): cstring {.
    importc: "gnutls_pk_get_name", gnutls_import.}
proc gnutls_pk_get_oid*(algorithm: gnutls_pk_algorithm_t): cstring {.
    importc: "gnutls_pk_get_oid", gnutls_import.}
proc gnutls_sign_get_name*(algorithm: gnutls_sign_algorithm_t): cstring {.
    importc: "gnutls_sign_get_name", gnutls_import.}
proc gnutls_sign_get_oid*(sign: gnutls_sign_algorithm_t): cstring {.
    importc: "gnutls_sign_get_oid", gnutls_import.}
proc gnutls_gost_paramset_get_name*(param: gnutls_gost_paramset_t): cstring {.
    importc: "gnutls_gost_paramset_get_name", gnutls_import.}
proc gnutls_gost_paramset_get_oid*(param: gnutls_gost_paramset_t): cstring {.
    importc: "gnutls_gost_paramset_get_oid", gnutls_import.}
proc gnutls_cipher_get_key_size*(algorithm: gnutls_cipher_algorithm_t): csize {.
    importc: "gnutls_cipher_get_key_size", gnutls_import.}
proc gnutls_mac_get_key_size*(algorithm: gnutls_mac_algorithm_t): csize {.
    importc: "gnutls_mac_get_key_size", gnutls_import.}
proc gnutls_sign_is_secure*(algorithm: gnutls_sign_algorithm_t): cuint {.
    importc: "gnutls_sign_is_secure", gnutls_import.}
##  It is possible that a signature algorithm is ok to use for short-lived
##  data (e.g., to sign a TLS session), but not for data that are long-lived
##  like certificates. This flag is about checking the security of the algorithm
##  for long-lived data.

const
  GNUTLS_SIGN_FLAG_SECURE_FOR_CERTS* = 1

proc gnutls_sign_is_secure2*(algorithm: gnutls_sign_algorithm_t; flags: cuint): cuint {.
    importc: "gnutls_sign_is_secure2", gnutls_import.}
proc gnutls_sign_get_hash_algorithm*(sign: gnutls_sign_algorithm_t): gnutls_digest_algorithm_t {.
    importc: "gnutls_sign_get_hash_algorithm", gnutls_import.}
proc gnutls_sign_get_pk_algorithm*(sign: gnutls_sign_algorithm_t): gnutls_pk_algorithm_t {.
    importc: "gnutls_sign_get_pk_algorithm", gnutls_import.}
proc gnutls_pk_to_sign*(pk: gnutls_pk_algorithm_t; hash: gnutls_digest_algorithm_t): gnutls_sign_algorithm_t {.
    importc: "gnutls_pk_to_sign", gnutls_import.}
proc gnutls_sign_supports_pk_algorithm*(sign: gnutls_sign_algorithm_t;
                                       pk: gnutls_pk_algorithm_t): cuint {.
    importc: "gnutls_sign_supports_pk_algorithm", gnutls_import.}
const
  gnutls_sign_algorithm_get_name* = gnutls_sign_get_name

proc gnutls_mac_get_id*(name: cstring): gnutls_mac_algorithm_t {.
    importc: "gnutls_mac_get_id", gnutls_import.}
proc gnutls_digest_get_id*(name: cstring): gnutls_digest_algorithm_t {.
    importc: "gnutls_digest_get_id", gnutls_import.}
proc gnutls_cipher_get_id*(name: cstring): gnutls_cipher_algorithm_t {.
    importc: "gnutls_cipher_get_id", gnutls_import.}
proc gnutls_kx_get_id*(name: cstring): gnutls_kx_algorithm_t {.
    importc: "gnutls_kx_get_id", gnutls_import.}
proc gnutls_protocol_get_id*(name: cstring): gnutls_protocol_t {.
    importc: "gnutls_protocol_get_id", gnutls_import.}
proc gnutls_certificate_type_get_id*(name: cstring): gnutls_certificate_type_t {.
    importc: "gnutls_certificate_type_get_id", gnutls_import.}
proc gnutls_pk_get_id*(name: cstring): gnutls_pk_algorithm_t {.
    importc: "gnutls_pk_get_id", gnutls_import.}
proc gnutls_sign_get_id*(name: cstring): gnutls_sign_algorithm_t {.
    importc: "gnutls_sign_get_id", gnutls_import.}
proc gnutls_ecc_curve_get_id*(name: cstring): gnutls_ecc_curve_t {.
    importc: "gnutls_ecc_curve_get_id", gnutls_import.}
proc gnutls_ecc_curve_get_pk*(curve: gnutls_ecc_curve_t): gnutls_pk_algorithm_t {.
    importc: "gnutls_ecc_curve_get_pk", gnutls_import.}
proc gnutls_group_get_id*(name: cstring): gnutls_group_t {.
    importc: "gnutls_group_get_id", gnutls_import.}
proc gnutls_oid_to_digest*(oid: cstring): gnutls_digest_algorithm_t {.
    importc: "gnutls_oid_to_digest", gnutls_import.}
proc gnutls_oid_to_mac*(oid: cstring): gnutls_mac_algorithm_t {.
    importc: "gnutls_oid_to_mac", gnutls_import.}
proc gnutls_oid_to_pk*(oid: cstring): gnutls_pk_algorithm_t {.
    importc: "gnutls_oid_to_pk", gnutls_import.}
proc gnutls_oid_to_sign*(oid: cstring): gnutls_sign_algorithm_t {.
    importc: "gnutls_oid_to_sign", gnutls_import.}
proc gnutls_oid_to_ecc_curve*(oid: cstring): gnutls_ecc_curve_t {.
    importc: "gnutls_oid_to_ecc_curve", gnutls_import.}
proc gnutls_oid_to_gost_paramset*(oid: cstring): gnutls_gost_paramset_t {.
    importc: "gnutls_oid_to_gost_paramset", gnutls_import.}
##  list supported algorithms

proc gnutls_ecc_curve_list*(): ptr gnutls_ecc_curve_t {.
    importc: "gnutls_ecc_curve_list", gnutls_import.}
proc gnutls_group_list*(): ptr gnutls_group_t {.importc: "gnutls_group_list",
    gnutls_import.}
proc gnutls_cipher_list*(): ptr gnutls_cipher_algorithm_t {.
    importc: "gnutls_cipher_list", gnutls_import.}
proc gnutls_mac_list*(): ptr gnutls_mac_algorithm_t {.importc: "gnutls_mac_list",
    gnutls_import.}
proc gnutls_digest_list*(): ptr gnutls_digest_algorithm_t {.
    importc: "gnutls_digest_list", gnutls_import.}
proc gnutls_protocol_list*(): ptr gnutls_protocol_t {.
    importc: "gnutls_protocol_list", gnutls_import.}
proc gnutls_certificate_type_list*(): ptr gnutls_certificate_type_t {.
    importc: "gnutls_certificate_type_list", gnutls_import.}
proc gnutls_kx_list*(): ptr gnutls_kx_algorithm_t {.importc: "gnutls_kx_list",
    gnutls_import.}
proc gnutls_pk_list*(): ptr gnutls_pk_algorithm_t {.importc: "gnutls_pk_list",
    gnutls_import.}
proc gnutls_sign_list*(): ptr gnutls_sign_algorithm_t {.importc: "gnutls_sign_list",
    gnutls_import.}
proc gnutls_cipher_suite_info*(idx: csize; cs_id: ptr cuchar;
                              kx: ptr gnutls_kx_algorithm_t;
                              cipher: ptr gnutls_cipher_algorithm_t;
                              mac: ptr gnutls_mac_algorithm_t;
                              min_version: ptr gnutls_protocol_t): cstring {.
    importc: "gnutls_cipher_suite_info", gnutls_import.}
##  error functions

proc gnutls_error_is_fatal*(error: cint): cint {.importc: "gnutls_error_is_fatal",
    gnutls_import.}
proc gnutls_error_to_alert*(err: cint; level: ptr cint): cint {.
    importc: "gnutls_error_to_alert", gnutls_import.}
proc gnutls_perror*(error: cint) {.importc: "gnutls_perror", gnutls_import.}
proc gnutls_strerror*(error: cint): cstring {.importc: "gnutls_strerror", gnutls_import.}
proc gnutls_strerror_name*(error: cint): cstring {.importc: "gnutls_strerror_name",
    gnutls_import.}
##  Semi-internal functions.
##

proc gnutls_handshake_set_private_extensions*(session: gnutls_session_t;
    allow: cint) {.importc: "gnutls_handshake_set_private_extensions", gnutls_import.}
proc gnutls_handshake_set_random*(session: gnutls_session_t;
                                 random: ptr gnutls_datum_t): cint {.
    importc: "gnutls_handshake_set_random", gnutls_import.}
proc gnutls_handshake_get_last_out*(session: gnutls_session_t): gnutls_handshake_description_t {.
    importc: "gnutls_handshake_get_last_out", gnutls_import.}
proc gnutls_handshake_get_last_in*(session: gnutls_session_t): gnutls_handshake_description_t {.
    importc: "gnutls_handshake_get_last_in", gnutls_import.}
##  Record layer functions.
##

const
  GNUTLS_HEARTBEAT_WAIT* = 1

proc gnutls_heartbeat_ping*(session: gnutls_session_t; data_size: csize;
                           max_tries: cuint; flags: cuint): cint {.
    importc: "gnutls_heartbeat_ping", gnutls_import.}
proc gnutls_heartbeat_pong*(session: gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_heartbeat_pong", gnutls_import.}
proc gnutls_record_set_timeout*(session: gnutls_session_t; ms: cuint) {.
    importc: "gnutls_record_set_timeout", gnutls_import.}
proc gnutls_record_disable_padding*(session: gnutls_session_t) {.
    importc: "gnutls_record_disable_padding", gnutls_import.}
proc gnutls_record_cork*(session: gnutls_session_t) {.
    importc: "gnutls_record_cork", gnutls_import.}
const
  GNUTLS_RECORD_WAIT* = 1

proc gnutls_record_uncork*(session: gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_record_uncork", gnutls_import.}
proc gnutls_record_discard_queued*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_discard_queued", gnutls_import.}
proc gnutls_record_get_state*(session: gnutls_session_t; read: cuint;
                             mac_key: ptr gnutls_datum_t; IV: ptr gnutls_datum_t;
                             cipher_key: ptr gnutls_datum_t;
                             seq_number: array[8, cuchar]): cint {.
    importc: "gnutls_record_get_state", gnutls_import.}
proc gnutls_record_set_state*(session: gnutls_session_t; read: cuint;
                             seq_number: array[8, cuchar]): cint {.
    importc: "gnutls_record_set_state", gnutls_import.}
type
  gnutls_range_st* {.bycopy.} = object
    low*: csize
    high*: csize


proc gnutls_range_split*(session: gnutls_session_t; orig: ptr gnutls_range_st;
                        small_range: ptr gnutls_range_st;
                        rem_range: ptr gnutls_range_st): cint {.
    importc: "gnutls_range_split", gnutls_import.}
proc gnutls_record_send*(session: gnutls_session_t; data: pointer; data_size: csize): ssize_t {.
    importc: "gnutls_record_send", gnutls_import.}
proc gnutls_record_send2*(session: gnutls_session_t; data: pointer; data_size: csize;
                         pad: csize; flags: cuint): ssize_t {.
    importc: "gnutls_record_send2", gnutls_import.}
proc gnutls_record_send_range*(session: gnutls_session_t; data: pointer;
                              data_size: csize; range: ptr gnutls_range_st): ssize_t {.
    importc: "gnutls_record_send_range", gnutls_import.}
proc gnutls_record_recv*(session: gnutls_session_t; data: pointer; data_size: csize): ssize_t {.
    importc: "gnutls_record_recv", gnutls_import.}
type
  mbuffer_st {.bycopy.} = object
  gnutls_packet_t* = ptr mbuffer_st

proc gnutls_record_recv_packet*(session: gnutls_session_t;
                               packet: ptr gnutls_packet_t): ssize_t {.
    importc: "gnutls_record_recv_packet", gnutls_import.}
proc gnutls_packet_get*(packet: gnutls_packet_t; data: ptr gnutls_datum_t;
                       sequence: ptr cuchar) {.importc: "gnutls_packet_get",
    gnutls_import.}
proc gnutls_packet_deinit*(packet: gnutls_packet_t) {.
    importc: "gnutls_packet_deinit", gnutls_import.}
const
  gnutls_read* = gnutls_record_recv
  gnutls_write* = gnutls_record_send

proc gnutls_record_recv_seq*(session: gnutls_session_t; data: pointer;
                            data_size: csize; seq: ptr cuchar): ssize_t {.
    importc: "gnutls_record_recv_seq", gnutls_import.}
proc gnutls_record_overhead_size*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_overhead_size", gnutls_import.}
proc gnutls_est_record_overhead_size*(version: gnutls_protocol_t;
                                     cipher: gnutls_cipher_algorithm_t;
                                     mac: gnutls_mac_algorithm_t;
                                     comp: gnutls_compression_method_t;
                                     flags: cuint): csize {.
    importc: "gnutls_est_record_overhead_size", gnutls_import.}
proc gnutls_session_enable_compatibility_mode*(session: gnutls_session_t) {.
    importc: "gnutls_session_enable_compatibility_mode", gnutls_import.}
template gnutls_record_set_max_empty_records*(session, x: untyped): void =
  nil

proc gnutls_record_can_use_length_hiding*(session: gnutls_session_t): cuint {.
    importc: "gnutls_record_can_use_length_hiding", gnutls_import.}
proc gnutls_record_get_direction*(session: gnutls_session_t): cint {.
    importc: "gnutls_record_get_direction", gnutls_import.}
proc gnutls_record_get_max_size*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_get_max_size", gnutls_import.}
proc gnutls_record_set_max_size*(session: gnutls_session_t; size: csize): ssize_t {.
    importc: "gnutls_record_set_max_size", gnutls_import.}
proc gnutls_record_check_pending*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_check_pending", gnutls_import.}
proc gnutls_record_check_corked*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_check_corked", gnutls_import.}
proc gnutls_record_get_max_early_data_size*(session: gnutls_session_t): csize {.
    importc: "gnutls_record_get_max_early_data_size", gnutls_import.}
proc gnutls_record_set_max_early_data_size*(session: gnutls_session_t; size: csize): cint {.
    importc: "gnutls_record_set_max_early_data_size", gnutls_import.}
proc gnutls_record_send_early_data*(session: gnutls_session_t; data: pointer;
                                   length: csize): ssize_t {.
    importc: "gnutls_record_send_early_data", gnutls_import.}
proc gnutls_record_recv_early_data*(session: gnutls_session_t; data: pointer;
                                   data_size: csize): ssize_t {.
    importc: "gnutls_record_recv_early_data", gnutls_import.}
proc gnutls_session_force_valid*(session: gnutls_session_t) {.
    importc: "gnutls_session_force_valid", gnutls_import.}
proc gnutls_prf*(session: gnutls_session_t; label_size: csize; label: cstring;
                server_random_first: cint; extra_size: csize; extra: cstring;
                outsize: csize; `out`: cstring): cint {.importc: "gnutls_prf",
    gnutls_import.}
proc gnutls_prf_rfc5705*(session: gnutls_session_t; label_size: csize;
                        label: cstring; context_size: csize; context: cstring;
                        outsize: csize; `out`: cstring): cint {.
    importc: "gnutls_prf_rfc5705", gnutls_import.}
proc gnutls_prf_raw*(session: gnutls_session_t; label_size: csize; label: cstring;
                    seed_size: csize; seed: cstring; outsize: csize; `out`: cstring): cint {.
    importc: "gnutls_prf_raw", gnutls_import.}
## *
##  gnutls_server_name_type_t:
##  @GNUTLS_NAME_DNS: Domain Name System name type.
##
##  Enumeration of different server name types.
##

type
  gnutls_server_name_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_NAME_DNS = 1


proc gnutls_server_name_set*(session: gnutls_session_t;
                            `type`: gnutls_server_name_type_t; name: pointer;
                            name_length: csize): cint {.
    importc: "gnutls_server_name_set", gnutls_import.}
proc gnutls_server_name_get*(session: gnutls_session_t; data: pointer;
                            data_length: ptr csize; `type`: ptr cuint; indx: cuint): cint {.
    importc: "gnutls_server_name_get", gnutls_import.}
proc gnutls_heartbeat_get_timeout*(session: gnutls_session_t): cuint {.
    importc: "gnutls_heartbeat_get_timeout", gnutls_import.}
proc gnutls_heartbeat_set_timeouts*(session: gnutls_session_t;
                                   retrans_timeout: cuint; total_timeout: cuint) {.
    importc: "gnutls_heartbeat_set_timeouts", gnutls_import.}
const
  GNUTLS_HB_PEER_ALLOWED_TO_SEND* = (1)
  GNUTLS_HB_PEER_NOT_ALLOWED_TO_SEND* = (1 shl 1)

##  Heartbeat

proc gnutls_heartbeat_enable*(session: gnutls_session_t; `type`: cuint) {.
    importc: "gnutls_heartbeat_enable", gnutls_import.}
const
  GNUTLS_HB_LOCAL_ALLOWED_TO_SEND* = (1 shl 2)

proc gnutls_heartbeat_allowed*(session: gnutls_session_t; `type`: cuint): cuint {.
    importc: "gnutls_heartbeat_allowed", gnutls_import.}
##  Safe renegotiation

proc gnutls_safe_renegotiation_status*(session: gnutls_session_t): cuint {.
    importc: "gnutls_safe_renegotiation_status", gnutls_import.}
proc gnutls_session_ext_master_secret_status*(session: gnutls_session_t): cuint {.
    importc: "gnutls_session_ext_master_secret_status", gnutls_import.}
proc gnutls_session_etm_status*(session: gnutls_session_t): cuint {.
    importc: "gnutls_session_etm_status", gnutls_import.}
## *
##  gnutls_session_flags_t:
##  @GNUTLS_SFLAGS_SAFE_RENEGOTIATION: Safe renegotiation (RFC5746) was used
##  @GNUTLS_SFLAGS_EXT_MASTER_SECRET: The extended master secret (RFC7627) extension was used
##  @GNUTLS_SFLAGS_ETM: The encrypt then MAC (RFC7366) extension was used
##  @GNUTLS_SFLAGS_RFC7919: The RFC7919 Diffie-Hellman parameters were negotiated
##  @GNUTLS_SFLAGS_HB_LOCAL_SEND: The heartbeat negotiation allows the local side to send heartbeat messages
##  @GNUTLS_SFLAGS_HB_PEER_SEND: The heartbeat negotiation allows the peer to send heartbeat messages
##  @GNUTLS_SFLAGS_FALSE_START: False start was used in this client session.
##  @GNUTLS_SFLAGS_SESSION_TICKET: A session ticket has been received by the server.
##  @GNUTLS_SFLAGS_POST_HANDSHAKE_AUTH: Indicates client capability for post-handshake auth; set only on server side.
##  @GNUTLS_SFLAGS_EARLY_START: The TLS1.3 server session returned early.
##  @GNUTLS_SFLAGS_EARLY_DATA: The TLS1.3 early data has been received by the server.
##
##  Enumeration of different session parameters.
##

type
  gnutls_session_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_SFLAGS_SAFE_RENEGOTIATION = 1,
    GNUTLS_SFLAGS_EXT_MASTER_SECRET = 1 shl 1, GNUTLS_SFLAGS_ETM = 1 shl 2,
    GNUTLS_SFLAGS_HB_LOCAL_SEND = 1 shl 3, GNUTLS_SFLAGS_HB_PEER_SEND = 1 shl 4,
    GNUTLS_SFLAGS_FALSE_START = 1 shl 5, GNUTLS_SFLAGS_RFC7919 = 1 shl 6,
    GNUTLS_SFLAGS_SESSION_TICKET = 1 shl 7,
    GNUTLS_SFLAGS_POST_HANDSHAKE_AUTH = 1 shl 8, GNUTLS_SFLAGS_EARLY_START = 1 shl 9,
    GNUTLS_SFLAGS_EARLY_DATA = 1 shl 10


proc gnutls_session_get_flags*(session: gnutls_session_t): cuint {.
    importc: "gnutls_session_get_flags", gnutls_import.}
## *
##  gnutls_supplemental_data_format_type_t:
##  @GNUTLS_SUPPLEMENTAL_UNKNOWN: Unknown data format
##
##  Enumeration of different supplemental data types (RFC 4680).
##

type
  gnutls_supplemental_data_format_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_SUPPLEMENTAL_UNKNOWN = 0


proc gnutls_supplemental_get_name*(`type`: gnutls_supplemental_data_format_type_t): cstring {.
    importc: "gnutls_supplemental_get_name", gnutls_import.}
##  SessionTicket, RFC 5077.

proc gnutls_session_ticket_key_generate*(key: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_ticket_key_generate", gnutls_import.}
proc gnutls_session_ticket_enable_client*(session: gnutls_session_t): cint {.
    importc: "gnutls_session_ticket_enable_client", gnutls_import.}
proc gnutls_session_ticket_enable_server*(session: gnutls_session_t;
    key: ptr gnutls_datum_t): cint {.importc: "gnutls_session_ticket_enable_server",
                                 gnutls_import.}
proc gnutls_session_ticket_send*(session: gnutls_session_t; nr: cuint; flags: cuint): cint {.
    importc: "gnutls_session_ticket_send", gnutls_import.}
##  SRTP, RFC 5764
## *
##  gnutls_srtp_profile_t:
##  @GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80: 128 bit AES with a 80 bit HMAC-SHA1
##  @GNUTLS_SRTP_AES128_CM_HMAC_SHA1_32: 128 bit AES with a 32 bit HMAC-SHA1
##  @GNUTLS_SRTP_NULL_HMAC_SHA1_80: NULL cipher with a 80 bit HMAC-SHA1
##  @GNUTLS_SRTP_NULL_HMAC_SHA1_32: NULL cipher with a 32 bit HMAC-SHA1
##
##  Enumeration of different SRTP protection profiles.
##

type
  gnutls_srtp_profile_t* {.size: sizeof(cint).} = enum
    GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80 = 0x00000001,
    GNUTLS_SRTP_AES128_CM_HMAC_SHA1_32 = 0x00000002,
    GNUTLS_SRTP_NULL_HMAC_SHA1_80 = 0x00000005,
    GNUTLS_SRTP_NULL_HMAC_SHA1_32 = 0x00000006


proc gnutls_srtp_set_profile*(session: gnutls_session_t;
                             profile: gnutls_srtp_profile_t): cint {.
    importc: "gnutls_srtp_set_profile", gnutls_import.}
proc gnutls_srtp_set_profile_direct*(session: gnutls_session_t; profiles: cstring;
                                    err_pos: cstringArray): cint {.
    importc: "gnutls_srtp_set_profile_direct", gnutls_import.}
proc gnutls_srtp_get_selected_profile*(session: gnutls_session_t;
                                      profile: ptr gnutls_srtp_profile_t): cint {.
    importc: "gnutls_srtp_get_selected_profile", gnutls_import.}
proc gnutls_srtp_get_profile_name*(profile: gnutls_srtp_profile_t): cstring {.
    importc: "gnutls_srtp_get_profile_name", gnutls_import.}
proc gnutls_srtp_get_profile_id*(name: cstring; profile: ptr gnutls_srtp_profile_t): cint {.
    importc: "gnutls_srtp_get_profile_id", gnutls_import.}
proc gnutls_srtp_get_keys*(session: gnutls_session_t; key_material: pointer;
                          key_material_size: cuint;
                          client_key: ptr gnutls_datum_t;
                          client_salt: ptr gnutls_datum_t;
                          server_key: ptr gnutls_datum_t;
                          server_salt: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srtp_get_keys", gnutls_import.}
proc gnutls_srtp_set_mki*(session: gnutls_session_t; mki: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srtp_set_mki", gnutls_import.}
proc gnutls_srtp_get_mki*(session: gnutls_session_t; mki: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srtp_get_mki", gnutls_import.}
##  ALPN TLS extension
## *
##  gnutls_alpn_flags_t:
##  @GNUTLS_ALPN_MANDATORY: Require ALPN negotiation. The connection will be
##    aborted if no matching ALPN protocol is found.
##  @GNUTLS_ALPN_SERVER_PRECEDENCE: The choices set by the server
##    will take precedence over the client's.
##
##  Enumeration of different ALPN flags. These are used by gnutls_alpn_set_protocols().
##

type
  gnutls_alpn_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_ALPN_MANDATORY = 1, GNUTLS_ALPN_SERVER_PRECEDENCE = (1 shl 1)


const
  GNUTLS_ALPN_MAND* = GNUTLS_ALPN_MANDATORY

proc gnutls_alpn_get_selected_protocol*(session: gnutls_session_t;
                                       protocol: ptr gnutls_datum_t): cint {.
    importc: "gnutls_alpn_get_selected_protocol", gnutls_import.}
proc gnutls_alpn_set_protocols*(session: gnutls_session_t;
                               protocols: ptr gnutls_datum_t;
                               protocols_size: cuint; flags: cuint): cint {.
    importc: "gnutls_alpn_set_protocols", gnutls_import.}
proc gnutls_key_generate*(key: ptr gnutls_datum_t; key_size: cuint): cint {.
    importc: "gnutls_key_generate", gnutls_import.}
const
  GNUTLS_PRIORITY_INIT_DEF_APPEND* = 1

proc gnutls_priority_init*(priority_cache: ptr gnutls_priority_t;
                          priorities: cstring; err_pos: cstringArray): cint {.
    importc: "gnutls_priority_init", gnutls_import.}
proc gnutls_priority_init2*(priority_cache: ptr gnutls_priority_t;
                           priorities: cstring; err_pos: cstringArray; flags: cuint): cint {.
    importc: "gnutls_priority_init2", gnutls_import.}
proc gnutls_priority_deinit*(priority_cache: gnutls_priority_t) {.
    importc: "gnutls_priority_deinit", gnutls_import.}
proc gnutls_priority_get_cipher_suite_index*(pcache: gnutls_priority_t; idx: cuint;
    sidx: ptr cuint): cint {.importc: "gnutls_priority_get_cipher_suite_index",
                         gnutls_import.}
const
  GNUTLS_PRIORITY_LIST_INIT_KEYWORDS* = 1
  GNUTLS_PRIORITY_LIST_SPECIAL* = 2

proc gnutls_priority_string_list*(iter: cuint; flags: cuint): cstring {.
    importc: "gnutls_priority_string_list", gnutls_import.}
proc gnutls_priority_set*(session: gnutls_session_t; priority: gnutls_priority_t): cint {.
    importc: "gnutls_priority_set", gnutls_import.}
proc gnutls_priority_set_direct*(session: gnutls_session_t; priorities: cstring;
                                err_pos: cstringArray): cint {.
    importc: "gnutls_priority_set_direct", gnutls_import.}
proc gnutls_priority_certificate_type_list*(pcache: gnutls_priority_t;
    list: ptr ptr cuint): cint {.importc: "gnutls_priority_certificate_type_list",
                            gnutls_import.}
proc gnutls_priority_certificate_type_list2*(pcache: gnutls_priority_t;
    list: ptr ptr cuint; target: gnutls_ctype_target_t): cint {.
    importc: "gnutls_priority_certificate_type_list2", gnutls_import.}
proc gnutls_priority_sign_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_sign_list", gnutls_import.}
proc gnutls_priority_protocol_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_protocol_list", gnutls_import.}
proc gnutls_priority_ecc_curve_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_ecc_curve_list", gnutls_import.}
proc gnutls_priority_group_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_group_list", gnutls_import.}
proc gnutls_priority_kx_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_kx_list", gnutls_import.}
proc gnutls_priority_cipher_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_cipher_list", gnutls_import.}
proc gnutls_priority_mac_list*(pcache: gnutls_priority_t; list: ptr ptr cuint): cint {.
    importc: "gnutls_priority_mac_list", gnutls_import.}
proc gnutls_set_default_priority*(session: gnutls_session_t): cint {.
    importc: "gnutls_set_default_priority", gnutls_import.}
proc gnutls_set_default_priority_append*(session: gnutls_session_t;
                                        add_prio: cstring; err_pos: cstringArray;
                                        flags: cuint): cint {.
    importc: "gnutls_set_default_priority_append", gnutls_import.}
##  Returns the name of a cipher suite

proc gnutls_cipher_suite_get_name*(kx_algorithm: gnutls_kx_algorithm_t;
                                  cipher_algorithm: gnutls_cipher_algorithm_t;
                                  mac_algorithm: gnutls_mac_algorithm_t): cstring {.
    importc: "gnutls_cipher_suite_get_name", gnutls_import.}
##  get the currently used protocol version

proc gnutls_protocol_get_version*(session: gnutls_session_t): gnutls_protocol_t {.
    importc: "gnutls_protocol_get_version", gnutls_import.}
proc gnutls_protocol_get_name*(version: gnutls_protocol_t): cstring {.
    importc: "gnutls_protocol_get_name", gnutls_import.}
##  get/set session
##

proc gnutls_session_set_data*(session: gnutls_session_t; session_data: pointer;
                             session_data_size: csize): cint {.
    importc: "gnutls_session_set_data", gnutls_import.}
proc gnutls_session_get_data*(session: gnutls_session_t; session_data: pointer;
                             session_data_size: ptr csize): cint {.
    importc: "gnutls_session_get_data", gnutls_import.}
proc gnutls_session_get_data2*(session: gnutls_session_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_get_data2", gnutls_import.}
proc gnutls_session_get_random*(session: gnutls_session_t;
                               client: ptr gnutls_datum_t;
                               server: ptr gnutls_datum_t) {.
    importc: "gnutls_session_get_random", gnutls_import.}
proc gnutls_session_get_master_secret*(session: gnutls_session_t;
                                      secret: ptr gnutls_datum_t) {.
    importc: "gnutls_session_get_master_secret", gnutls_import.}
proc gnutls_session_get_desc*(session: gnutls_session_t): cstring {.
    importc: "gnutls_session_get_desc", gnutls_import.}
type
  gnutls_certificate_verify_function* = proc (a1: gnutls_session_t): cint

proc gnutls_session_set_verify_function*(session: gnutls_session_t; `func`: ptr gnutls_certificate_verify_function) {.
    importc: "gnutls_session_set_verify_function", gnutls_import.}
## *
##  gnutls_vdata_types_t:
##  @GNUTLS_DT_UNKNOWN: Unknown data type.
##  @GNUTLS_DT_DNS_HOSTNAME: The data contain a null-terminated DNS hostname; the hostname will be
##    matched using the RFC6125 rules. If the data contain a textual IP (v4 or v6) address it will
##    be marched against the IPAddress Alternative name, unless the verification flag %GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES
##    is specified.
##  @GNUTLS_DT_IP_ADDRESS: The data contain a raw IP address (4 or 16 bytes). If will be matched
##    against the IPAddress Alternative name; option available since 3.6.0.
##  @GNUTLS_DT_RFC822NAME: The data contain a null-terminated email address; the email will be
##    matched against the RFC822Name Alternative name of the certificate, or the EMAIL DN component if the
##    former isn't available. Prior to matching the email address will be converted to ACE
##    (ASCII-compatible-encoding).
##  @GNUTLS_DT_KEY_PURPOSE_OID: The data contain a null-terminated key purpose OID. It will be matched
##    against the certificate's Extended Key Usage extension.
##
##  Enumeration of different typed-data options. They are used as input to certificate
##  verification functions to provide information about the name and purpose of the
##  certificate. Only a single option of a type can be provided to the relevant functions
##  (i.e., options %GNUTLS_DT_DNS_HOSTNAME, %GNUTLS_DT_IP_ADDRESS and
##  %GNUTLS_DT_RFC822NAME cannot be combined).
##

type
  gnutls_vdata_types_t* {.size: sizeof(cint).} = enum
    GNUTLS_DT_UNKNOWN = 0, GNUTLS_DT_DNS_HOSTNAME = 1, GNUTLS_DT_KEY_PURPOSE_OID = 2,
    GNUTLS_DT_RFC822NAME = 3, GNUTLS_DT_IP_ADDRESS = 4
  gnutls_typed_vdata_st* {.bycopy.} = object
    `type`*: gnutls_vdata_types_t
    data*: ptr cuchar
    size*: cuint



proc gnutls_session_set_verify_cert*(session: gnutls_session_t; hostname: cstring;
                                    flags: cuint) {.
    importc: "gnutls_session_set_verify_cert", gnutls_import.}
proc gnutls_session_set_verify_cert2*(session: gnutls_session_t;
                                     data: ptr gnutls_typed_vdata_st;
                                     elements: cuint; flags: cuint) {.
    importc: "gnutls_session_set_verify_cert2", gnutls_import.}
proc gnutls_session_get_verify_cert_status*(a1: gnutls_session_t): cuint {.
    importc: "gnutls_session_get_verify_cert_status", gnutls_import.}
proc gnutls_session_set_premaster*(session: gnutls_session_t; entity: cuint;
                                  version: gnutls_protocol_t;
                                  kx: gnutls_kx_algorithm_t;
                                  cipher: gnutls_cipher_algorithm_t;
                                  mac: gnutls_mac_algorithm_t;
                                  comp: gnutls_compression_method_t;
                                  master: ptr gnutls_datum_t;
                                  session_id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_set_premaster", gnutls_import.}
##  returns the session ID

const
  GNUTLS_MAX_SESSION_ID* = 32

proc gnutls_session_get_id*(session: gnutls_session_t; session_id: pointer;
                           session_id_size: ptr csize): cint {.
    importc: "gnutls_session_get_id", gnutls_import.}
proc gnutls_session_get_id2*(session: gnutls_session_t;
                            session_id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_get_id2", gnutls_import.}
proc gnutls_session_set_id*(session: gnutls_session_t; sid: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_set_id", gnutls_import.}
proc gnutls_session_channel_binding*(session: gnutls_session_t;
                                    cbtype: gnutls_channel_binding_t;
                                    cb: ptr gnutls_datum_t): cint {.
    importc: "gnutls_session_channel_binding", gnutls_import.}
##  checks if this session is a resumed one
##

proc gnutls_session_is_resumed*(session: gnutls_session_t): cint {.
    importc: "gnutls_session_is_resumed", gnutls_import.}
proc gnutls_session_resumption_requested*(session: gnutls_session_t): cint {.
    importc: "gnutls_session_resumption_requested", gnutls_import.}
type
  gnutls_db_store_func* = proc (a1: pointer; key: gnutls_datum_t; data: gnutls_datum_t): cint
  gnutls_db_remove_func* = proc (a1: pointer; key: gnutls_datum_t): cint
  gnutls_db_retr_func* = proc (a1: pointer; key: gnutls_datum_t): gnutls_datum_t

proc gnutls_db_set_cache_expiration*(session: gnutls_session_t; seconds: cint) {.
    importc: "gnutls_db_set_cache_expiration", gnutls_import.}
proc gnutls_db_get_default_cache_expiration*(): cuint {.
    importc: "gnutls_db_get_default_cache_expiration", gnutls_import.}
proc gnutls_db_remove_session*(session: gnutls_session_t) {.
    importc: "gnutls_db_remove_session", gnutls_import.}
proc gnutls_db_set_retrieve_function*(session: gnutls_session_t;
                                     retr_func: gnutls_db_retr_func) {.
    importc: "gnutls_db_set_retrieve_function", gnutls_import.}
proc gnutls_db_set_remove_function*(session: gnutls_session_t;
                                   rem_func: gnutls_db_remove_func) {.
    importc: "gnutls_db_set_remove_function", gnutls_import.}
proc gnutls_db_set_store_function*(session: gnutls_session_t;
                                  store_func: gnutls_db_store_func) {.
    importc: "gnutls_db_set_store_function", gnutls_import.}
proc gnutls_db_set_ptr*(session: gnutls_session_t; `ptr`: pointer) {.
    importc: "gnutls_db_set_ptr", gnutls_import.}
proc gnutls_db_get_ptr*(session: gnutls_session_t): pointer {.
    importc: "gnutls_db_get_ptr", gnutls_import.}
proc gnutls_db_check_entry*(session: gnutls_session_t;
                           session_entry: gnutls_datum_t): cint {.
    importc: "gnutls_db_check_entry", gnutls_import.}
proc gnutls_db_check_entry_time*(entry: ptr gnutls_datum_t): time_t {.
    importc: "gnutls_db_check_entry_time", gnutls_import.}
proc gnutls_db_check_entry_expire_time*(entry: ptr gnutls_datum_t): time_t {.
    importc: "gnutls_db_check_entry_expire_time", gnutls_import.}
## *
##  gnutls_handshake_hook_func:
##  @session: the current session
##  @htype: the type of the handshake message (%gnutls_handshake_description_t)
##  @when: non zero if this is a post-process/generation call and zero otherwise
##  @incoming: non zero if this is an incoming message and zero if this is an outgoing message
##  @msg: the (const) data of the handshake message without the handshake headers.
##
##  Function prototype for handshake hooks. It is set using
##  gnutls_handshake_set_hook_function().
##
##  Returns: Non zero on error.
##

const
  GNUTLS_HOOK_POST* = (1)
  GNUTLS_HOOK_PRE* = (0)
  GNUTLS_HOOK_BOTH* = (-1)

type
  gnutls_handshake_hook_func* = proc (a1: gnutls_session_t; htype: cuint;
                                   `when`: cuint; incoming: cuint;
                                   msg: ptr gnutls_datum_t): cint

proc gnutls_handshake_set_hook_function*(session: gnutls_session_t; htype: cuint;
                                        `when`: cint;
                                        `func`: gnutls_handshake_hook_func) {.
    importc: "gnutls_handshake_set_hook_function", gnutls_import.}

type
  gnutls_handshake_simple_hook_func* = proc (a1: gnutls_session_t): cint

#const gnutls_handshake_post_client_hello_func* = gnutls_handshake_simple_hook_func

proc gnutls_handshake_set_post_client_hello_function*(session: gnutls_session_t;
    `func`: gnutls_handshake_simple_hook_func) {.
    importc: "gnutls_handshake_set_post_client_hello_function", gnutls_import.}
proc gnutls_handshake_set_max_packet_length*(session: gnutls_session_t; max: csize) {.
    importc: "gnutls_handshake_set_max_packet_length", gnutls_import.}
##  returns libgnutls version (call it with a NULL argument)
##

proc gnutls_check_version*(req_version: cstring): cstring {.
    importc: "gnutls_check_version", gnutls_import.}
##  A macro which will allow optimizing out calls to gnutls_check_version()
##  when the version being compiled with is sufficient.
##  Used as:
##    if (gnutls_check_version_numerc(3,3,16)) {
##
## #define gnutls_check_version_numeric(a,b,c) \
## 	((GNUTLS_VERSION_MAJOR >= (a)) &&  \
## 	 ((GNUTLS_VERSION_NUMBER >= ( ((a) << 16) + ((b) << 8) + (c) )) || \
## 	 gnutls_check_version(#a "." #b "." #c)))
##  Functions for setting/clearing credentials
##

proc gnutls_credentials_clear*(session: gnutls_session_t) {.
    importc: "gnutls_credentials_clear", gnutls_import.}
##  cred is a structure defined by the kx algorithm
##

proc gnutls_credentials_set*(session: gnutls_session_t;
                            `type`: gnutls_credentials_type_t; cred: pointer): cint {.
    importc: "gnutls_credentials_set", gnutls_import.}
proc gnutls_credentials_get*(session: gnutls_session_t;
                            `type`: gnutls_credentials_type_t; cred: ptr pointer): cint {.
    importc: "gnutls_credentials_get", gnutls_import.}
const
  gnutls_cred_set* = gnutls_credentials_set

##  x.509 types

type
  gnutls_pubkey_st* {.bycopy.} = object

  gnutls_pubkey_t* = ptr gnutls_pubkey_st
  gnutls_privkey_st* {.bycopy.} = object

  gnutls_privkey_t* = ptr gnutls_privkey_st
  gnutls_x509_privkey_t* = ptr gnutls_x509_privkey_int
  gnutls_x509_crl_int* {.bycopy.} = object

  gnutls_x509_crl_t* = ptr gnutls_x509_crl_int
  gnutls_x509_crt_int* {.bycopy.} = object

  gnutls_x509_crt_t* = ptr gnutls_x509_crt_int
  gnutls_x509_crq_int* {.bycopy.} = object

  gnutls_x509_crq_t* = ptr gnutls_x509_crq_int
  gnutls_openpgp_keyring_int* {.bycopy.} = object

  gnutls_openpgp_keyring_t* = ptr gnutls_openpgp_keyring_int

##  Credential structures - used in gnutls_credentials_set();

type
  gnutls_certificate_credentials_st* {.bycopy.} = object

  gnutls_certificate_credentials_t* = ptr gnutls_certificate_credentials_st
  gnutls_certificate_server_credentials* = gnutls_certificate_credentials_t
  gnutls_certificate_client_credentials* = gnutls_certificate_credentials_t
  gnutls_anon_server_credentials_st* {.bycopy.} = object
  gnutls_anon_client_credentials_st {.bycopy.} = object
  gnutls_anon_server_credentials_t* = ptr gnutls_anon_server_credentials_st
  gnutls_anon_client_credentials_t* = ptr gnutls_anon_client_credentials_st

proc gnutls_anon_free_server_credentials*(sc: gnutls_anon_server_credentials_t) {.
    importc: "gnutls_anon_free_server_credentials", gnutls_import.}
proc gnutls_anon_allocate_server_credentials*(
    sc: ptr gnutls_anon_server_credentials_t): cint {.
    importc: "gnutls_anon_allocate_server_credentials", gnutls_import.}
proc gnutls_anon_set_server_dh_params*(res: gnutls_anon_server_credentials_t;
                                      dh_params: gnutls_dh_params_t) {.
    importc: "gnutls_anon_set_server_dh_params", gnutls_import.}
proc gnutls_anon_set_server_known_dh_params*(
    res: gnutls_anon_server_credentials_t; sec_param: gnutls_sec_param_t): cint {.
    importc: "gnutls_anon_set_server_known_dh_params", gnutls_import.}
proc gnutls_anon_set_server_params_function*(
    res: gnutls_anon_server_credentials_t; `func`: ptr gnutls_params_function) {.
    importc: "gnutls_anon_set_server_params_function", gnutls_import.}
proc gnutls_anon_free_client_credentials*(sc: gnutls_anon_client_credentials_t) {.
    importc: "gnutls_anon_free_client_credentials", gnutls_import.}
proc gnutls_anon_allocate_client_credentials*(
    sc: ptr gnutls_anon_client_credentials_t): cint {.
    importc: "gnutls_anon_allocate_client_credentials", gnutls_import.}
##  CERTFILE is an x509 certificate in PEM form.
##  KEYFILE is a pkcs-1 private key in PEM form (for RSA keys).
##

proc gnutls_certificate_free_credentials*(sc: gnutls_certificate_credentials_t) {.
    importc: "gnutls_certificate_free_credentials", gnutls_import.}
proc gnutls_certificate_allocate_credentials*(
    res: ptr gnutls_certificate_credentials_t): cint {.
    importc: "gnutls_certificate_allocate_credentials", gnutls_import.}
proc gnutls_certificate_get_issuer*(sc: gnutls_certificate_credentials_t;
                                   cert: gnutls_x509_crt_t;
                                   issuer: ptr gnutls_x509_crt_t; flags: cuint): cint {.
    importc: "gnutls_certificate_get_issuer", gnutls_import.}
proc gnutls_certificate_get_crt_raw*(sc: gnutls_certificate_credentials_t;
                                    idx1: cuint; idx2: cuint;
                                    cert: ptr gnutls_datum_t): cint {.
    importc: "gnutls_certificate_get_crt_raw", gnutls_import.}
proc gnutls_certificate_free_keys*(sc: gnutls_certificate_credentials_t) {.
    importc: "gnutls_certificate_free_keys", gnutls_import.}
proc gnutls_certificate_free_cas*(sc: gnutls_certificate_credentials_t) {.
    importc: "gnutls_certificate_free_cas", gnutls_import.}
proc gnutls_certificate_free_ca_names*(sc: gnutls_certificate_credentials_t) {.
    importc: "gnutls_certificate_free_ca_names", gnutls_import.}
proc gnutls_certificate_free_crls*(sc: gnutls_certificate_credentials_t) {.
    importc: "gnutls_certificate_free_crls", gnutls_import.}
proc gnutls_certificate_set_dh_params*(res: gnutls_certificate_credentials_t;
                                      dh_params: gnutls_dh_params_t) {.
    importc: "gnutls_certificate_set_dh_params", gnutls_import.}
proc gnutls_certificate_set_known_dh_params*(
    res: gnutls_certificate_credentials_t; sec_param: gnutls_sec_param_t): cint {.
    importc: "gnutls_certificate_set_known_dh_params", gnutls_import.}
proc gnutls_certificate_set_verify_flags*(res: gnutls_certificate_credentials_t;
    flags: cuint) {.importc: "gnutls_certificate_set_verify_flags", gnutls_import.}
proc gnutls_certificate_get_verify_flags*(res: gnutls_certificate_credentials_t): cuint {.
    importc: "gnutls_certificate_get_verify_flags", gnutls_import.}
## *
##  gnutls_certificate_flags:
##  @GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH: Skip the key and certificate matching check.
##  @GNUTLS_CERTIFICATE_API_V2: If set the gnutls_certificate_set_*key* functions will return an index of the added key pair instead of zero.
##  @GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK: If set, the gnutls_certificate_set_ocsp_status_request_file
##     function, will not check whether the response set matches any of the certificates.
##  @GNUTLS_CERTIFICATE_VERIFY_CRLS: This will enable CRL verification when added in the certificate structure.
##     When used, it requires CAs to be added before CRLs.
##
##  Enumeration of different certificate credentials flags.
##

type
  gnutls_certificate_flags* {.size: sizeof(cint).} = enum
    GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH = 1,
    GNUTLS_CERTIFICATE_API_V2 = (1 shl 1),
    GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK = (1 shl 2),
    GNUTLS_CERTIFICATE_VERIFY_CRLS = (1 shl 3)


proc gnutls_certificate_set_flags*(a1: gnutls_certificate_credentials_t;
                                  flags: cuint) {.
    importc: "gnutls_certificate_set_flags", gnutls_import.}
proc gnutls_certificate_set_verify_limits*(res: gnutls_certificate_credentials_t;
    max_bits: cuint; max_depth: cuint) {.importc: "gnutls_certificate_set_verify_limits",
                                     gnutls_import.}
proc gnutls_certificate_set_x509_system_trust*(
    cred: gnutls_certificate_credentials_t): cint {.
    importc: "gnutls_certificate_set_x509_system_trust", gnutls_import.}
proc gnutls_certificate_set_x509_trust_file*(
    cred: gnutls_certificate_credentials_t; cafile: cstring;
    `type`: gnutls_x509_crt_fmt_t): cint {.importc: "gnutls_certificate_set_x509_trust_file",
                                        gnutls_import.}
proc gnutls_certificate_set_x509_trust_dir*(
    cred: gnutls_certificate_credentials_t; ca_dir: cstring;
    `type`: gnutls_x509_crt_fmt_t): cint {.importc: "gnutls_certificate_set_x509_trust_dir",
                                        gnutls_import.}
proc gnutls_certificate_set_x509_trust_mem*(
    res: gnutls_certificate_credentials_t; ca: ptr gnutls_datum_t;
    `type`: gnutls_x509_crt_fmt_t): cint {.importc: "gnutls_certificate_set_x509_trust_mem",
                                        gnutls_import.}
proc gnutls_certificate_set_x509_crl_file*(res: gnutls_certificate_credentials_t;
    crlfile: cstring; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_x509_crl_file", gnutls_import.}
proc gnutls_certificate_set_x509_crl_mem*(res: gnutls_certificate_credentials_t;
    CRL: ptr gnutls_datum_t; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_x509_crl_mem", gnutls_import.}
proc gnutls_certificate_set_x509_key_file*(res: gnutls_certificate_credentials_t;
    certfile: cstring; keyfile: cstring; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_x509_key_file", gnutls_import.}
proc gnutls_certificate_set_x509_key_file2*(
    res: gnutls_certificate_credentials_t; certfile: cstring; keyfile: cstring;
    `type`: gnutls_x509_crt_fmt_t; pass: cstring; flags: cuint): cint {.
    importc: "gnutls_certificate_set_x509_key_file2", gnutls_import.}
proc gnutls_certificate_set_x509_key_mem*(res: gnutls_certificate_credentials_t;
    cert: ptr gnutls_datum_t; key: ptr gnutls_datum_t; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_certificate_set_x509_key_mem", gnutls_import.}
proc gnutls_certificate_set_x509_key_mem2*(res: gnutls_certificate_credentials_t;
    cert: ptr gnutls_datum_t; key: ptr gnutls_datum_t; `type`: gnutls_x509_crt_fmt_t;
    pass: cstring; flags: cuint): cint {.importc: "gnutls_certificate_set_x509_key_mem2",
                                    gnutls_import.}
proc gnutls_certificate_send_x509_rdn_sequence*(session: gnutls_session_t;
    status: cint) {.importc: "gnutls_certificate_send_x509_rdn_sequence",
                  gnutls_import.}
proc gnutls_certificate_set_x509_simple_pkcs12_file*(
    res: gnutls_certificate_credentials_t; pkcs12file: cstring;
    `type`: gnutls_x509_crt_fmt_t; password: cstring): cint {.
    importc: "gnutls_certificate_set_x509_simple_pkcs12_file", gnutls_import.}
proc gnutls_certificate_set_x509_simple_pkcs12_mem*(
    res: gnutls_certificate_credentials_t; p12blob: ptr gnutls_datum_t;
    `type`: gnutls_x509_crt_fmt_t; password: cstring): cint {.
    importc: "gnutls_certificate_set_x509_simple_pkcs12_mem", gnutls_import.}
##  New functions to allow setting already parsed X.509 stuff.
##

proc gnutls_certificate_set_x509_key*(res: gnutls_certificate_credentials_t;
                                     cert_list: ptr gnutls_x509_crt_t;
                                     cert_list_size: cint;
                                     key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_certificate_set_x509_key", gnutls_import.}
proc gnutls_certificate_set_x509_trust*(res: gnutls_certificate_credentials_t;
                                       ca_list: ptr gnutls_x509_crt_t;
                                       ca_list_size: cint): cint {.
    importc: "gnutls_certificate_set_x509_trust", gnutls_import.}
proc gnutls_certificate_set_x509_crl*(res: gnutls_certificate_credentials_t;
                                     crl_list: ptr gnutls_x509_crl_t;
                                     crl_list_size: cint): cint {.
    importc: "gnutls_certificate_set_x509_crl", gnutls_import.}
proc gnutls_certificate_get_x509_key*(res: gnutls_certificate_credentials_t;
                                     index: cuint; key: ptr gnutls_x509_privkey_t): cint {.
    importc: "gnutls_certificate_get_x509_key", gnutls_import.}
proc gnutls_certificate_get_x509_crt*(res: gnutls_certificate_credentials_t;
                                     index: cuint;
                                     crt_list: ptr ptr gnutls_x509_crt_t;
                                     crt_list_size: ptr cuint): cint {.
    importc: "gnutls_certificate_get_x509_crt", gnutls_import.}
##  OCSP status request extension, RFC 6066

type
  gnutls_status_request_ocsp_func* = proc (session: gnutls_session_t; `ptr`: pointer;
                                        ocsp_response: ptr gnutls_datum_t): cint

proc gnutls_certificate_set_ocsp_status_request_function*(
    res: gnutls_certificate_credentials_t;
    ocsp_func: gnutls_status_request_ocsp_func; `ptr`: pointer) {.
    importc: "gnutls_certificate_set_ocsp_status_request_function", gnutls_import.}
proc gnutls_certificate_set_ocsp_status_request_function2*(
    res: gnutls_certificate_credentials_t; idx: cuint;
    ocsp_func: gnutls_status_request_ocsp_func; `ptr`: pointer): cint {.
    importc: "gnutls_certificate_set_ocsp_status_request_function2", gnutls_import.}
proc gnutls_certificate_set_ocsp_status_request_file*(
    res: gnutls_certificate_credentials_t; response_file: cstring; idx: cuint): cint {.
    importc: "gnutls_certificate_set_ocsp_status_request_file", gnutls_import.}
proc gnutls_certificate_set_ocsp_status_request_file2*(
    res: gnutls_certificate_credentials_t; response_file: cstring; idx: cuint;
    fmt: gnutls_x509_crt_fmt_t): cint {.importc: "gnutls_certificate_set_ocsp_status_request_file2",
                                     gnutls_import.}
proc gnutls_certificate_set_ocsp_status_request_mem*(
    res: gnutls_certificate_credentials_t; resp: ptr gnutls_datum_t; idx: cuint;
    fmt: gnutls_x509_crt_fmt_t): cint {.importc: "gnutls_certificate_set_ocsp_status_request_mem",
                                     gnutls_import.}
type
  gnutls_ocsp_data_st* {.bycopy.} = object
    version*: cuint            ##  must be zero
    response*: gnutls_datum_t
    exptime*: time_t
    padding*: array[32, cuchar]


proc gnutls_certificate_get_ocsp_expiration*(
    sc: gnutls_certificate_credentials_t; idx: cuint; oidx: cint; flags: cuint): time_t {.
    importc: "gnutls_certificate_get_ocsp_expiration", gnutls_import.}
proc gnutls_ocsp_status_request_enable_client*(session: gnutls_session_t;
    responder_id: ptr gnutls_datum_t; responder_id_size: csize;
    request_extensions: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_status_request_enable_client", gnutls_import.}
proc gnutls_ocsp_status_request_get*(session: gnutls_session_t;
                                    response: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_status_request_get", gnutls_import.}
const
  GNUTLS_OCSP_SR_IS_AVAIL* = 1

proc gnutls_ocsp_status_request_is_checked*(session: gnutls_session_t; flags: cuint): cint {.
    importc: "gnutls_ocsp_status_request_is_checked", gnutls_import.}
proc gnutls_ocsp_status_request_get2*(session: gnutls_session_t; idx: cuint;
                                     response: ptr gnutls_datum_t): cint {.
    importc: "gnutls_ocsp_status_request_get2", gnutls_import.}
##  RAW public key functions (RFC7250)

proc gnutls_certificate_set_rawpk_key_mem*(
    cred: gnutls_certificate_credentials_t; spki: ptr gnutls_datum_t;
    pkey: ptr gnutls_datum_t; format: gnutls_x509_crt_fmt_t; pass: cstring;
    key_usage: cuint; names: cstringArray; names_length: cuint; flags: cuint): cint {.
    importc: "gnutls_certificate_set_rawpk_key_mem", gnutls_import.}
proc gnutls_certificate_set_rawpk_key_file*(
    cred: gnutls_certificate_credentials_t; rawpkfile: cstring;
    privkeyfile: cstring; format: gnutls_x509_crt_fmt_t; pass: cstring;
    key_usage: cuint; names: cstringArray; names_length: cuint; privkey_flags: cuint;
    pkcs11_flags: cuint): cint {.importc: "gnutls_certificate_set_rawpk_key_file",
                              gnutls_import.}
##  global state functions
##

proc gnutls_global_init*(): cint {.importc: "gnutls_global_init", gnutls_import.}
proc gnutls_global_deinit*() {.importc: "gnutls_global_deinit", gnutls_import.}
## *
##  gnutls_time_func:
##  @t: where to store time.
##
##  Function prototype for time()-like function.  Set with
##  gnutls_global_set_time_function().
##
##  Returns: Number of seconds since the epoch, or (time_t)-1 on errors.
##

type
  gnutls_time_func* = proc (t: ptr time_t): time_t
  mutex_init_func* = proc (mutex: ptr pointer): cint
  mutex_lock_func* = proc (mutex: ptr pointer): cint
  mutex_unlock_func* = proc (mutex: ptr pointer): cint
  mutex_deinit_func* = proc (mutex: ptr pointer): cint

proc gnutls_global_set_mutex*(init: mutex_init_func; deinit: mutex_deinit_func;
                             lock: mutex_lock_func; unlock: mutex_unlock_func) {.
    importc: "gnutls_global_set_mutex", gnutls_import.}
type
  gnutls_alloc_function* = proc (a1: csize): pointer
  gnutls_calloc_function* = proc (a1: csize; a2: csize): pointer
  gnutls_is_secure_function* = proc (a1: pointer): cint
  gnutls_free_function* = proc (a1: pointer)
  gnutls_realloc_function* = proc (a1: pointer; a2: csize): pointer

proc gnutls_free*(d:  gnutls_datum_t) {.
  importc: "gnutls_free", gnutls_import.}

proc gnutls_global_set_time_function*(time_func: gnutls_time_func) {.
    importc: "gnutls_global_set_time_function", gnutls_import.}
##  For use in callbacks
##  FIXME
## extern _SYM_EXPORT gnutls_alloc_function gnutls_malloc;
## extern _SYM_EXPORT gnutls_realloc_function gnutls_realloc;
## extern _SYM_EXPORT gnutls_calloc_function gnutls_calloc;
## extern _SYM_EXPORT gnutls_free_function gnutls_free;
##
## extern _SYM_EXPORT char *(*gnutls_strdup) (const char *);
##  a variant of memset that doesn't get optimized out

proc gnutls_memset*(data: pointer; c: cint; size: csize) {.importc: "gnutls_memset",
    gnutls_import.}
##  constant time memcmp

proc gnutls_memcmp*(s1: pointer; s2: pointer; n: csize): cint {.
    importc: "gnutls_memcmp", gnutls_import.}
type
  gnutls_log_func* = proc (a1: cint; a2: cstring)
  gnutls_audit_log_func* = proc (a1: gnutls_session_t; a2: cstring)

proc gnutls_global_set_log_function*(log_func: gnutls_log_func) {.
    importc: "gnutls_global_set_log_function", gnutls_import.}
proc gnutls_global_set_audit_log_function*(log_func: gnutls_audit_log_func) {.
    importc: "gnutls_global_set_audit_log_function", gnutls_import.}
proc gnutls_global_set_log_level*(level: cint) {.
    importc: "gnutls_global_set_log_level", gnutls_import.}
##  Diffie-Hellman parameter handling.
##

proc gnutls_dh_params_init*(dh_params: ptr gnutls_dh_params_t): cint {.
    importc: "gnutls_dh_params_init", gnutls_import.}
proc gnutls_dh_params_deinit*(dh_params: gnutls_dh_params_t) {.
    importc: "gnutls_dh_params_deinit", gnutls_import.}
proc gnutls_dh_params_import_raw*(dh_params: gnutls_dh_params_t;
                                 prime: ptr gnutls_datum_t;
                                 generator: ptr gnutls_datum_t): cint {.
    importc: "gnutls_dh_params_import_raw", gnutls_import.}
proc gnutls_dh_params_import_dsa*(dh_params: gnutls_dh_params_t;
                                 key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_dh_params_import_dsa", gnutls_import.}
proc gnutls_dh_params_import_raw2*(dh_params: gnutls_dh_params_t;
                                  prime: ptr gnutls_datum_t;
                                  generator: ptr gnutls_datum_t; key_bits: cuint): cint {.
    importc: "gnutls_dh_params_import_raw2", gnutls_import.}
proc gnutls_dh_params_import_pkcs3*(params: gnutls_dh_params_t;
                                   pkcs3_params: ptr gnutls_datum_t;
                                   format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_dh_params_import_pkcs3", gnutls_import.}
proc gnutls_dh_params_generate2*(params: gnutls_dh_params_t; bits: cuint): cint {.
    importc: "gnutls_dh_params_generate2", gnutls_import.}
proc gnutls_dh_params_export_pkcs3*(params: gnutls_dh_params_t;
                                   format: gnutls_x509_crt_fmt_t;
                                   params_data: ptr cuchar;
                                   params_data_size: ptr csize): cint {.
    importc: "gnutls_dh_params_export_pkcs3", gnutls_import.}
proc gnutls_dh_params_export2_pkcs3*(params: gnutls_dh_params_t;
                                    format: gnutls_x509_crt_fmt_t;
                                    `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_dh_params_export2_pkcs3", gnutls_import.}
proc gnutls_dh_params_export_raw*(params: gnutls_dh_params_t;
                                 prime: ptr gnutls_datum_t;
                                 generator: ptr gnutls_datum_t; bits: ptr cuint): cint {.
    importc: "gnutls_dh_params_export_raw", gnutls_import.}
proc gnutls_dh_params_cpy*(dst: gnutls_dh_params_t; src: gnutls_dh_params_t): cint {.
    importc: "gnutls_dh_params_cpy", gnutls_import.}
##  Session stuff
##

type
  iovec {.bycopy.} = object
  giovec_t* = iovec
  gnutls_pull_func* = proc (a1: gnutls_transport_ptr_t; a2: pointer; a3: csize): ssize_t
  gnutls_push_func* = proc (a1: gnutls_transport_ptr_t; a2: pointer; a3: csize): ssize_t

proc gnutls_system_recv_timeout*(`ptr`: gnutls_transport_ptr_t; ms: cuint): cint {.
    importc: "gnutls_system_recv_timeout", gnutls_import.}
type
  gnutls_pull_timeout_func* = proc (a1: gnutls_transport_ptr_t; ms: cuint): cint
  gnutls_vec_push_func* = proc (a1: gnutls_transport_ptr_t; iov: ptr giovec_t;
                             iovcnt: cint): ssize_t
  gnutls_errno_func* = proc (a1: gnutls_transport_ptr_t): cint

proc gnutls_transport_set_int2*(session: gnutls_session_t; r: cint; s: cint) {.
    importc: "gnutls_transport_set_int2", gnutls_import.}
template gnutls_transport_set_int*(s, i: untyped): untyped =
  gnutls_transport_set_int2(s, i, i)

proc gnutls_transport_get_int2*(session: gnutls_session_t; r: ptr cint; s: ptr cint) {.
    importc: "gnutls_transport_get_int2", gnutls_import.}
proc gnutls_transport_get_int*(session: gnutls_session_t): cint {.
    importc: "gnutls_transport_get_int", gnutls_import.}
proc gnutls_transport_set_ptr*(session: gnutls_session_t;
                              `ptr`: gnutls_transport_ptr_t) {.
    importc: "gnutls_transport_set_ptr", gnutls_import.}
proc gnutls_transport_set_ptr2*(session: gnutls_session_t;
                               recv_ptr: gnutls_transport_ptr_t;
                               send_ptr: gnutls_transport_ptr_t) {.
    importc: "gnutls_transport_set_ptr2", gnutls_import.}
proc gnutls_transport_get_ptr*(session: gnutls_session_t): gnutls_transport_ptr_t {.
    importc: "gnutls_transport_get_ptr", gnutls_import.}
proc gnutls_transport_get_ptr2*(session: gnutls_session_t;
                               recv_ptr: ptr gnutls_transport_ptr_t;
                               send_ptr: ptr gnutls_transport_ptr_t) {.
    importc: "gnutls_transport_get_ptr2", gnutls_import.}
proc gnutls_transport_set_vec_push_function*(session: gnutls_session_t;
    vec_func: gnutls_vec_push_func) {.importc: "gnutls_transport_set_vec_push_function",
                                    gnutls_import.}
proc gnutls_transport_set_push_function*(session: gnutls_session_t;
                                        push_func: gnutls_push_func) {.
    importc: "gnutls_transport_set_push_function", gnutls_import.}
proc gnutls_transport_set_pull_function*(session: gnutls_session_t;
                                        pull_func: gnutls_pull_func) {.
    importc: "gnutls_transport_set_pull_function", gnutls_import.}
proc gnutls_transport_set_pull_timeout_function*(session: gnutls_session_t;
    `func`: gnutls_pull_timeout_func) {.importc: "gnutls_transport_set_pull_timeout_function",
                                      gnutls_import.}
proc gnutls_transport_set_errno_function*(session: gnutls_session_t;
    errno_func: gnutls_errno_func) {.importc: "gnutls_transport_set_errno_function",
                                   gnutls_import.}
proc gnutls_transport_set_errno*(session: gnutls_session_t; err: cint) {.
    importc: "gnutls_transport_set_errno", gnutls_import.}
##  session specific
##

proc gnutls_session_set_ptr*(session: gnutls_session_t; `ptr`: pointer) {.
    importc: "gnutls_session_set_ptr", gnutls_import.}
proc gnutls_session_get_ptr*(session: gnutls_session_t): pointer {.
    importc: "gnutls_session_get_ptr", gnutls_import.}
proc gnutls_openpgp_send_cert*(session: gnutls_session_t;
                              status: gnutls_openpgp_crt_status_t) {.
    importc: "gnutls_openpgp_send_cert", gnutls_import.}
##  This function returns the hash of the given data.
##

proc gnutls_fingerprint*(algo: gnutls_digest_algorithm_t; data: ptr gnutls_datum_t;
                        result: pointer; result_size: ptr csize): cint {.
    importc: "gnutls_fingerprint", gnutls_import.}
## *
##  gnutls_random_art_t:
##  @GNUTLS_RANDOM_ART_OPENSSH: OpenSSH-style random art.
##
##  Enumeration of different random art types.
##

type
  gnutls_random_art_t* {.size: sizeof(cint).} = enum
    GNUTLS_RANDOM_ART_OPENSSH = 1


proc gnutls_random_art*(`type`: gnutls_random_art_t; key_type: cstring;
                       key_size: cuint; fpr: pointer; fpr_size: csize;
                       art: ptr gnutls_datum_t): cint {.
    importc: "gnutls_random_art", gnutls_import.}
##  IDNA

const
  GNUTLS_IDNA_FORCE_2008* = (1 shl 1)

proc gnutls_idna_map*(input: cstring; ilen: cuint; `out`: ptr gnutls_datum_t;
                     flags: cuint): cint {.importc: "gnutls_idna_map", gnutls_import.}
proc gnutls_idna_reverse_map*(input: cstring; ilen: cuint; `out`: ptr gnutls_datum_t;
                             flags: cuint): cint {.
    importc: "gnutls_idna_reverse_map", gnutls_import.}
##  SRP
##

type
  gnutls_srp_server_credentials_st {.bycopy.} = object
  gnutls_srp_client_credentials_st {.bycopy.} = object
  gnutls_srp_server_credentials_t* = ptr gnutls_srp_server_credentials_st
  gnutls_srp_client_credentials_t* = ptr gnutls_srp_client_credentials_st

proc gnutls_srp_free_client_credentials*(sc: gnutls_srp_client_credentials_t) {.
    importc: "gnutls_srp_free_client_credentials", gnutls_import.}
proc gnutls_srp_allocate_client_credentials*(
    sc: ptr gnutls_srp_client_credentials_t): cint {.
    importc: "gnutls_srp_allocate_client_credentials", gnutls_import.}
proc gnutls_srp_set_client_credentials*(res: gnutls_srp_client_credentials_t;
                                       username: cstring; password: cstring): cint {.
    importc: "gnutls_srp_set_client_credentials", gnutls_import.}
proc gnutls_srp_free_server_credentials*(sc: gnutls_srp_server_credentials_t) {.
    importc: "gnutls_srp_free_server_credentials", gnutls_import.}
proc gnutls_srp_allocate_server_credentials*(
    sc: ptr gnutls_srp_server_credentials_t): cint {.
    importc: "gnutls_srp_allocate_server_credentials", gnutls_import.}
proc gnutls_srp_set_server_credentials_file*(
    res: gnutls_srp_server_credentials_t; password_file: cstring;
    password_conf_file: cstring): cint {.importc: "gnutls_srp_set_server_credentials_file",
                                      gnutls_import.}
proc gnutls_srp_server_get_username*(session: gnutls_session_t): cstring {.
    importc: "gnutls_srp_server_get_username", gnutls_import.}
proc gnutls_srp_set_prime_bits*(session: gnutls_session_t; bits: cuint) {.
    importc: "gnutls_srp_set_prime_bits", gnutls_import.}
proc gnutls_srp_verifier*(username: cstring; password: cstring;
                         salt: ptr gnutls_datum_t; generator: ptr gnutls_datum_t;
                         prime: ptr gnutls_datum_t; res: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srp_verifier", gnutls_import.}
##  The static parameters defined in draft-ietf-tls-srp-05
##  Those should be used as input to gnutls_srp_verifier().
##
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_8192_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_8192_group_generator;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_4096_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_4096_group_generator;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_3072_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_3072_group_generator;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_2048_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_2048_group_generator;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_1536_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_1536_group_generator;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_1024_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_srp_1024_group_generator;
##  The static parameters defined in rfc7919
##
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_8192_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_8192_group_generator;
## extern _SYM_EXPORT const unsigned int gnutls_ffdhe_8192_key_bits;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_6144_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_6144_group_generator;
## extern _SYM_EXPORT const unsigned int gnutls_ffdhe_6144_key_bits;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_4096_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_4096_group_generator;
## extern _SYM_EXPORT const unsigned int gnutls_ffdhe_4096_key_bits;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_3072_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_3072_group_generator;
## extern _SYM_EXPORT const unsigned int gnutls_ffdhe_3072_key_bits;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_2048_group_prime;
## extern _SYM_EXPORT const gnutls_datum_t gnutls_ffdhe_2048_group_generator;
## extern _SYM_EXPORT const unsigned int gnutls_ffdhe_2048_key_bits;

type
  gnutls_srp_server_credentials_function* = proc (a1: gnutls_session_t;
      username: cstring; salt: ptr gnutls_datum_t; verifier: ptr gnutls_datum_t;
      generator: ptr gnutls_datum_t; prime: ptr gnutls_datum_t): cint

proc gnutls_srp_set_server_credentials_function*(
    cred: gnutls_srp_server_credentials_t;
    `func`: ptr gnutls_srp_server_credentials_function) {.
    importc: "gnutls_srp_set_server_credentials_function", gnutls_import.}
type
  gnutls_srp_client_credentials_function* = proc (a1: gnutls_session_t;
      a2: cstringArray; a3: cstringArray): cint

proc gnutls_srp_set_client_credentials_function*(
    cred: gnutls_srp_client_credentials_t;
    `func`: ptr gnutls_srp_client_credentials_function) {.
    importc: "gnutls_srp_set_client_credentials_function", gnutls_import.}
proc gnutls_srp_base64_encode*(data: ptr gnutls_datum_t; result: cstring;
                              result_size: ptr csize): cint {.
    importc: "gnutls_srp_base64_encode", gnutls_import.}
proc gnutls_srp_base64_encode2*(data: ptr gnutls_datum_t; result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srp_base64_encode2", gnutls_import.}
proc gnutls_srp_base64_decode*(b64_data: ptr gnutls_datum_t; result: cstring;
                              result_size: ptr csize): cint {.
    importc: "gnutls_srp_base64_decode", gnutls_import.}
proc gnutls_srp_base64_decode2*(b64_data: ptr gnutls_datum_t;
                               result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_srp_base64_decode2", gnutls_import.}
const
  gnutls_srp_base64_encode_alloc* = gnutls_srp_base64_encode2
  gnutls_srp_base64_decode_alloc* = gnutls_srp_base64_decode2

proc gnutls_srp_set_server_fake_salt_seed*(sc: gnutls_srp_server_credentials_t;
    seed: ptr gnutls_datum_t; salt_length: cuint) {.
    importc: "gnutls_srp_set_server_fake_salt_seed", gnutls_import.}
##  PSK stuff

type
  gnutls_psk_server_credentials_st = object
  gnutls_psk_client_credentials_st = object
  gnutls_psk_server_credentials_t* = ptr gnutls_psk_server_credentials_st
  gnutls_psk_client_credentials_t* = ptr gnutls_psk_client_credentials_st

## *
##  gnutls_psk_key_flags:
##  @GNUTLS_PSK_KEY_RAW: PSK-key in raw format.
##  @GNUTLS_PSK_KEY_HEX: PSK-key in hex format.
##
##  Enumeration of different PSK key flags.
##

type
  gnutls_psk_key_flags* {.size: sizeof(cint).} = enum
    GNUTLS_PSK_KEY_RAW = 0, GNUTLS_PSK_KEY_HEX


proc gnutls_psk_free_client_credentials*(sc: gnutls_psk_client_credentials_t) {.
    importc: "gnutls_psk_free_client_credentials", gnutls_import.}
proc gnutls_psk_allocate_client_credentials*(
    sc: ptr gnutls_psk_client_credentials_t): cint {.
    importc: "gnutls_psk_allocate_client_credentials", gnutls_import.}
proc gnutls_psk_set_client_credentials*(res: gnutls_psk_client_credentials_t;
                                       username: cstring; key: ptr gnutls_datum_t;
                                       flags: gnutls_psk_key_flags): cint {.
    importc: "gnutls_psk_set_client_credentials", gnutls_import.}
proc gnutls_psk_free_server_credentials*(sc: gnutls_psk_server_credentials_t) {.
    importc: "gnutls_psk_free_server_credentials", gnutls_import.}
proc gnutls_psk_allocate_server_credentials*(
    sc: ptr gnutls_psk_server_credentials_t): cint {.
    importc: "gnutls_psk_allocate_server_credentials", gnutls_import.}
proc gnutls_psk_set_server_credentials_file*(
    res: gnutls_psk_server_credentials_t; password_file: cstring): cint {.
    importc: "gnutls_psk_set_server_credentials_file", gnutls_import.}
proc gnutls_psk_set_server_credentials_hint*(
    res: gnutls_psk_server_credentials_t; hint: cstring): cint {.
    importc: "gnutls_psk_set_server_credentials_hint", gnutls_import.}
proc gnutls_psk_server_get_username*(session: gnutls_session_t): cstring {.
    importc: "gnutls_psk_server_get_username", gnutls_import.}
proc gnutls_psk_client_get_hint*(session: gnutls_session_t): cstring {.
    importc: "gnutls_psk_client_get_hint", gnutls_import.}
type
  gnutls_psk_server_credentials_function* = proc (a1: gnutls_session_t;
      username: cstring; key: ptr gnutls_datum_t): cint

proc gnutls_psk_set_server_credentials_function*(
    cred: gnutls_psk_server_credentials_t;
    `func`: ptr gnutls_psk_server_credentials_function) {.
    importc: "gnutls_psk_set_server_credentials_function", gnutls_import.}
type
  gnutls_psk_client_credentials_function* = proc (a1: gnutls_session_t;
      username: cstringArray; key: ptr gnutls_datum_t): cint

proc gnutls_psk_set_client_credentials_function*(
    cred: gnutls_psk_client_credentials_t;
    `func`: ptr gnutls_psk_client_credentials_function) {.
    importc: "gnutls_psk_set_client_credentials_function", gnutls_import.}
proc gnutls_hex_encode*(data: ptr gnutls_datum_t; result: cstring;
                       result_size: ptr csize): cint {.importc: "gnutls_hex_encode",
    gnutls_import.}
proc gnutls_hex_decode*(hex_data: ptr gnutls_datum_t; result: pointer;
                       result_size: ptr csize): cint {.importc: "gnutls_hex_decode",
    gnutls_import.}
proc gnutls_hex_encode2*(data: ptr gnutls_datum_t; result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_hex_encode2", gnutls_import.}
proc gnutls_hex_decode2*(data: ptr gnutls_datum_t; result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_hex_decode2", gnutls_import.}
proc gnutls_psk_set_server_dh_params*(res: gnutls_psk_server_credentials_t;
                                     dh_params: gnutls_dh_params_t) {.
    importc: "gnutls_psk_set_server_dh_params", gnutls_import.}
proc gnutls_psk_set_server_known_dh_params*(res: gnutls_psk_server_credentials_t;
    sec_param: gnutls_sec_param_t): cint {.importc: "gnutls_psk_set_server_known_dh_params",
                                        gnutls_import.}
proc gnutls_psk_set_server_params_function*(res: gnutls_psk_server_credentials_t;
    `func`: ptr gnutls_params_function) {.importc: "gnutls_psk_set_server_params_function",
                                       gnutls_import.}
## *
##  gnutls_x509_subject_alt_name_t:
##  @GNUTLS_SAN_DNSNAME: DNS-name SAN.
##  @GNUTLS_SAN_RFC822NAME: E-mail address SAN.
##  @GNUTLS_SAN_URI: URI SAN.
##  @GNUTLS_SAN_IPADDRESS: IP address SAN.
##  @GNUTLS_SAN_OTHERNAME: OtherName SAN.
##  @GNUTLS_SAN_DN: DN SAN.
##  @GNUTLS_SAN_OTHERNAME_XMPP: Virtual SAN, used by certain functions for convenience.
##  @GNUTLS_SAN_OTHERNAME_KRB5PRINCIPAL: Virtual SAN, used by certain functions for convenience.
##
##  Enumeration of different subject alternative names types.
##

type
  gnutls_x509_subject_alt_name_t* {.size: sizeof(cint).} = enum
    GNUTLS_SAN_DNSNAME = 1, GNUTLS_SAN_RFC822NAME = 2, GNUTLS_SAN_URI = 3,
    GNUTLS_SAN_IPADDRESS = 4, GNUTLS_SAN_OTHERNAME = 5, GNUTLS_SAN_DN = 6,
    GNUTLS_SAN_OTHERNAME_XMPP = 1000, GNUTLS_SAN_OTHERNAME_KRB5PRINCIPAL

const
  GNUTLS_SAN_MAX = GNUTLS_SAN_DN

type
  gnutls_openpgp_crt_int* {.bycopy.} = object

  gnutls_openpgp_crt_t* = ptr gnutls_openpgp_crt_int
  gnutls_openpgp_privkey_int* {.bycopy.} = object

  gnutls_openpgp_privkey_t* = ptr gnutls_openpgp_privkey_int
  gnutls_pkcs11_privkey_st* {.bycopy.} = object

  gnutls_pkcs11_privkey_t* = ptr gnutls_pkcs11_privkey_st

## *
##  gnutls_privkey_type_t:
##  @GNUTLS_PRIVKEY_X509: X.509 private key, #gnutls_x509_privkey_t.
##  @GNUTLS_PRIVKEY_OPENPGP: OpenPGP private key, #gnutls_openpgp_privkey_t.
##  @GNUTLS_PRIVKEY_PKCS11: PKCS11 private key, #gnutls_pkcs11_privkey_t.
##  @GNUTLS_PRIVKEY_EXT: External private key, operating using callbacks.
##
##  Enumeration of different private key types.
##

type
  INNER_C_UNION_gnutls_2599* {.bycopy.} = object {.union.}
    x509*: ptr gnutls_x509_crt_t
    pgp*: gnutls_openpgp_crt_t

  INNER_C_UNION_gnutls_2605* {.bycopy.} = object {.union.}
    x509*: gnutls_x509_privkey_t
    pgp*: gnutls_openpgp_privkey_t
    pkcs11*: gnutls_pkcs11_privkey_t

  gnutls_privkey_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_PRIVKEY_X509, GNUTLS_PRIVKEY_OPENPGP, GNUTLS_PRIVKEY_PKCS11,
    GNUTLS_PRIVKEY_EXT
  gnutls_retr2_st* {.bycopy.} = object
    cert_type*: gnutls_certificate_type_t
    key_type*: gnutls_privkey_type_t
    cert*: INNER_C_UNION_gnutls_2599
    ncerts*: cuint             ##  one for pgp keys
    key*: INNER_C_UNION_gnutls_2605
    deinit_all*: cuint         ##  if non zero all keys will be deinited



##  Functions that allow auth_info_t structures handling
##

proc gnutls_auth_get_type*(session: gnutls_session_t): gnutls_credentials_type_t {.
    importc: "gnutls_auth_get_type", gnutls_import.}
proc gnutls_auth_server_get_type*(session: gnutls_session_t): gnutls_credentials_type_t {.
    importc: "gnutls_auth_server_get_type", gnutls_import.}
proc gnutls_auth_client_get_type*(session: gnutls_session_t): gnutls_credentials_type_t {.
    importc: "gnutls_auth_client_get_type", gnutls_import.}
##  DH

proc gnutls_dh_set_prime_bits*(session: gnutls_session_t; bits: cuint) {.
    importc: "gnutls_dh_set_prime_bits", gnutls_import.}
proc gnutls_dh_get_secret_bits*(session: gnutls_session_t): cint {.
    importc: "gnutls_dh_get_secret_bits", gnutls_import.}
proc gnutls_dh_get_peers_public_bits*(session: gnutls_session_t): cint {.
    importc: "gnutls_dh_get_peers_public_bits", gnutls_import.}
proc gnutls_dh_get_prime_bits*(session: gnutls_session_t): cint {.
    importc: "gnutls_dh_get_prime_bits", gnutls_import.}
proc gnutls_dh_get_group*(session: gnutls_session_t; raw_gen: ptr gnutls_datum_t;
                         raw_prime: ptr gnutls_datum_t): cint {.
    importc: "gnutls_dh_get_group", gnutls_import.}
proc gnutls_dh_get_pubkey*(session: gnutls_session_t; raw_key: ptr gnutls_datum_t): cint {.
    importc: "gnutls_dh_get_pubkey", gnutls_import.}
##  X509PKI
##  These are set on the credentials structure.
##
##  use gnutls_certificate_set_retrieve_function2() in abstract.h
##  instead. It's much more efficient.
##

type
  gnutls_certificate_retrieve_function* = proc (a1: gnutls_session_t;
      req_ca_rdn: ptr gnutls_datum_t; nreqs: cint;
      pk_algos: ptr gnutls_pk_algorithm_t; pk_algos_length: cint;
      a6: ptr gnutls_retr2_st): cint

proc gnutls_certificate_set_retrieve_function*(
    cred: gnutls_certificate_credentials_t;
    `func`: ptr gnutls_certificate_retrieve_function) {.
    importc: "gnutls_certificate_set_retrieve_function", gnutls_import.}
proc gnutls_certificate_set_verify_function*(
    cred: gnutls_certificate_credentials_t;
    `func`: ptr gnutls_certificate_verify_function) {.
    importc: "gnutls_certificate_set_verify_function", gnutls_import.}
proc gnutls_certificate_server_set_request*(session: gnutls_session_t;
    req: gnutls_certificate_request_t) {.importc: "gnutls_certificate_server_set_request",
                                       gnutls_import.}
##  get data from the session
##

proc gnutls_certificate_get_peers*(session: gnutls_session_t; list_size: ptr cuint): ptr gnutls_datum_t {.
    importc: "gnutls_certificate_get_peers", gnutls_import.}
proc gnutls_certificate_get_ours*(session: gnutls_session_t): ptr gnutls_datum_t {.
    importc: "gnutls_certificate_get_ours", gnutls_import.}
proc gnutls_certificate_get_peers_subkey_id*(session: gnutls_session_t;
    id: ptr gnutls_datum_t): cint {.importc: "gnutls_certificate_get_peers_subkey_id",
                                gnutls_import.}
proc gnutls_certificate_activation_time_peers*(session: gnutls_session_t): time_t {.
    importc: "gnutls_certificate_activation_time_peers", gnutls_import.}
proc gnutls_certificate_expiration_time_peers*(session: gnutls_session_t): time_t {.
    importc: "gnutls_certificate_expiration_time_peers", gnutls_import.}
proc gnutls_certificate_client_get_request_status*(session: gnutls_session_t): cuint {.
    importc: "gnutls_certificate_client_get_request_status", gnutls_import.}
proc gnutls_certificate_verify_peers2*(session: gnutls_session_t; status: ptr cuint): cint {.
    importc: "gnutls_certificate_verify_peers2", gnutls_import.}
proc gnutls_certificate_verify_peers3*(session: gnutls_session_t;
                                      hostname: cstring; status: ptr cuint): cint {.
    importc: "gnutls_certificate_verify_peers3", gnutls_import.}
proc gnutls_certificate_verify_peers*(session: gnutls_session_t;
                                     data: ptr gnutls_typed_vdata_st;
                                     elements: cuint; status: ptr cuint): cint {.
    importc: "gnutls_certificate_verify_peers", gnutls_import.}
proc gnutls_certificate_verification_status_print*(status: cuint;
    `type`: gnutls_certificate_type_t; `out`: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_certificate_verification_status_print", gnutls_import.}
proc gnutls_pem_base64_encode*(msg: cstring; data: ptr gnutls_datum_t;
                              result: cstring; result_size: ptr csize): cint {.
    importc: "gnutls_pem_base64_encode", gnutls_import.}
proc gnutls_pem_base64_decode*(header: cstring; b64_data: ptr gnutls_datum_t;
                              result: ptr cuchar; result_size: ptr csize): cint {.
    importc: "gnutls_pem_base64_decode", gnutls_import.}
proc gnutls_pem_base64_encode2*(msg: cstring; data: ptr gnutls_datum_t;
                               result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pem_base64_encode2", gnutls_import.}
proc gnutls_pem_base64_decode2*(header: cstring; b64_data: ptr gnutls_datum_t;
                               result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_pem_base64_decode2", gnutls_import.}
proc gnutls_base64_encode2*(data: ptr gnutls_datum_t; result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_base64_encode2", gnutls_import.}
proc gnutls_base64_decode2*(b64_data: ptr gnutls_datum_t; result: ptr gnutls_datum_t): cint {.
    importc: "gnutls_base64_decode2", gnutls_import.}
const
  gnutls_pem_base64_encode_alloc* = gnutls_pem_base64_encode2
  gnutls_pem_base64_decode_alloc* = gnutls_pem_base64_decode2

##  key_usage will be an OR of the following values:
##
##  when the key is to be used for signing:

const
  GNUTLS_KEY_DIGITAL_SIGNATURE* = 128
  GNUTLS_KEY_NON_REPUDIATION* = 64

##  when the key is to be used for encryption:

const
  GNUTLS_KEY_KEY_ENCIPHERMENT* = 32
  GNUTLS_KEY_DATA_ENCIPHERMENT* = 16
  GNUTLS_KEY_KEY_AGREEMENT* = 8
  GNUTLS_KEY_KEY_CERT_SIGN* = 4
  GNUTLS_KEY_CRL_SIGN* = 2
  GNUTLS_KEY_ENCIPHER_ONLY* = 1
  GNUTLS_KEY_DECIPHER_ONLY* = 32768

proc gnutls_certificate_set_params_function*(
    res: gnutls_certificate_credentials_t; `func`: ptr gnutls_params_function) {.
    importc: "gnutls_certificate_set_params_function", gnutls_import.}
proc gnutls_anon_set_params_function*(res: gnutls_anon_server_credentials_t;
                                     `func`: ptr gnutls_params_function) {.
    importc: "gnutls_anon_set_params_function", gnutls_import.}
proc gnutls_psk_set_params_function*(res: gnutls_psk_server_credentials_t;
                                    `func`: ptr gnutls_params_function) {.
    importc: "gnutls_psk_set_params_function", gnutls_import.}
proc gnutls_hex2bin*(hex_data: cstring; hex_size: csize; bin_data: pointer;
                    bin_size: ptr csize): cint {.importc: "gnutls_hex2bin",
    gnutls_import.}
##  Trust on first use (or ssh like) functions
##  stores the provided information to a database
##

type
  gnutls_tdb_store_func* = proc (db_name: cstring; host: cstring; service: cstring;
                              expiration: time_t; pubkey: ptr gnutls_datum_t): cint
  gnutls_tdb_store_commitment_func* = proc (db_name: cstring; host: cstring;
      service: cstring; expiration: time_t; hash_algo: gnutls_digest_algorithm_t;
      hash: ptr gnutls_datum_t): cint

##  searches for the provided host/service pair that match the
##  provided public key in the database.

type
  gnutls_tdb_verify_func* = proc (db_name: cstring; host: cstring; service: cstring;
                               pubkey: ptr gnutls_datum_t): cint
  gnutls_tdb_int* {.bycopy.} = object

  gnutls_tdb_t* = ptr gnutls_tdb_int

proc gnutls_tdb_init*(tdb: ptr gnutls_tdb_t): cint {.importc: "gnutls_tdb_init",
    gnutls_import.}
proc gnutls_tdb_set_store_func*(tdb: gnutls_tdb_t; store: gnutls_tdb_store_func) {.
    importc: "gnutls_tdb_set_store_func", gnutls_import.}
proc gnutls_tdb_set_store_commitment_func*(tdb: gnutls_tdb_t;
    cstore: gnutls_tdb_store_commitment_func) {.
    importc: "gnutls_tdb_set_store_commitment_func", gnutls_import.}
proc gnutls_tdb_set_verify_func*(tdb: gnutls_tdb_t; verify: gnutls_tdb_verify_func) {.
    importc: "gnutls_tdb_set_verify_func", gnutls_import.}
proc gnutls_tdb_deinit*(tdb: gnutls_tdb_t) {.importc: "gnutls_tdb_deinit",
    gnutls_import.}
proc gnutls_verify_stored_pubkey*(db_name: cstring; tdb: gnutls_tdb_t; host: cstring;
                                 service: cstring;
                                 cert_type: gnutls_certificate_type_t;
                                 cert: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_verify_stored_pubkey", gnutls_import.}
const
  GNUTLS_SCOMMIT_FLAG_ALLOW_BROKEN* = 1

proc gnutls_store_commitment*(db_name: cstring; tdb: gnutls_tdb_t; host: cstring;
                             service: cstring;
                             hash_algo: gnutls_digest_algorithm_t;
                             hash: ptr gnutls_datum_t; expiration: time_t;
                             flags: cuint): cint {.
    importc: "gnutls_store_commitment", gnutls_import.}
proc gnutls_store_pubkey*(db_name: cstring; tdb: gnutls_tdb_t; host: cstring;
                         service: cstring; cert_type: gnutls_certificate_type_t;
                         cert: ptr gnutls_datum_t; expiration: time_t; flags: cuint): cint {.
    importc: "gnutls_store_pubkey", gnutls_import.}
##  Other helper functions

proc gnutls_load_file*(filename: cstring; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_load_file", gnutls_import.}
proc gnutls_url_is_supported*(url: cstring): cuint {.
    importc: "gnutls_url_is_supported", gnutls_import.}
##  PIN callback
## *
##  gnutls_pin_flag_t:
##  @GNUTLS_PIN_USER: The PIN for the user.
##  @GNUTLS_PIN_SO: The PIN for the security officer (admin).
##  @GNUTLS_PIN_CONTEXT_SPECIFIC: The PIN is for a specific action and key like signing.
##  @GNUTLS_PIN_FINAL_TRY: This is the final try before blocking.
##  @GNUTLS_PIN_COUNT_LOW: Few tries remain before token blocks.
##  @GNUTLS_PIN_WRONG: Last given PIN was not correct.
##
##  Enumeration of different flags that are input to the PIN function.
##

type
  gnutls_pin_flag_t* {.size: sizeof(cint).} = enum
    GNUTLS_PIN_USER = (1 shl 0), GNUTLS_PIN_SO = (1 shl 1),
    GNUTLS_PIN_FINAL_TRY = (1 shl 2), GNUTLS_PIN_COUNT_LOW = (1 shl 3),
    GNUTLS_PIN_CONTEXT_SPECIFIC = (1 shl 4), GNUTLS_PIN_WRONG = (1 shl 5)


const
  GNUTLS_PKCS11_PIN_USER* = GNUTLS_PIN_USER
  GNUTLS_PKCS11_PIN_SO* = GNUTLS_PIN_SO
  GNUTLS_PKCS11_PIN_FINAL_TRY* = GNUTLS_PIN_FINAL_TRY
  GNUTLS_PKCS11_PIN_COUNT_LOW* = GNUTLS_PIN_COUNT_LOW
  GNUTLS_PKCS11_PIN_CONTEXT_SPECIFIC* = GNUTLS_PIN_CONTEXT_SPECIFIC
  GNUTLS_PKCS11_PIN_WRONG* = GNUTLS_PIN_WRONG

## *
##  gnutls_pin_callback_t:
##  @userdata: user-controlled data from gnutls_pkcs11_set_pin_function().
##  @attempt: pin-attempt counter, initially 0.
##  @token_url: URL of token.
##  @token_label: label of token.
##  @flags: a #gnutls_pin_flag_t flag.
##  @pin: buffer to hold PIN, of size @pin_max.
##  @pin_max: size of @pin buffer.
##
##  Callback function type for PKCS#11 or TPM PIN entry.  It is set by
##  functions like gnutls_pkcs11_set_pin_function().
##
##  The callback should provides the PIN code to unlock the token with
##  label @token_label, specified by the URL @token_url.
##
##  The PIN code, as a NUL-terminated ASCII string, should be copied
##  into the @pin buffer (of maximum size @pin_max), and return 0 to
##  indicate success.  Alternatively, the callback may return a
##  negative gnutls error code to indicate failure and cancel PIN entry
##  (in which case, the contents of the @pin parameter are ignored).
##
##  When a PIN is required, the callback will be invoked repeatedly
##  (and indefinitely) until either the returned PIN code is correct,
##  the callback returns failure, or the token refuses login (e.g. when
##  the token is locked due to too many incorrect PINs!).  For the
##  first such invocation, the @attempt counter will have value zero;
##  it will increase by one for each subsequent attempt.
##
##  Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code on error.
##
##  Since: 2.12.0
##

type
  gnutls_pin_callback_t* = proc (userdata: pointer; attempt: cint; token_url: cstring;
                              token_label: cstring; flags: cuint; pin: cstring;
                              pin_max: csize): cint

proc gnutls_certificate_set_pin_function*(a1: gnutls_certificate_credentials_t;
    fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_certificate_set_pin_function", gnutls_import.}
##  Public string related functions

type
  gnutls_buffer_st = object
  gnutls_buffer_t* = ptr gnutls_buffer_st

proc gnutls_buffer_append_data*(a1: gnutls_buffer_t; data: pointer; data_size: csize): cint {.
    importc: "gnutls_buffer_append_data", gnutls_import.}
const
  GNUTLS_UTF8_IGNORE_ERRS* = 1

proc gnutls_utf8_password_normalize*(password: ptr cuchar; password_len: cuint;
                                    `out`: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_utf8_password_normalize", gnutls_import.}
##  Public extensions related functions

type
  gnutls_ext_priv_data_t* = pointer

proc gnutls_ext_set_data*(session: gnutls_session_t; `type`: cuint;
                         a3: gnutls_ext_priv_data_t) {.
    importc: "gnutls_ext_set_data", gnutls_import.}
proc gnutls_ext_get_data*(session: gnutls_session_t; `type`: cuint;
                         a3: ptr gnutls_ext_priv_data_t): cint {.
    importc: "gnutls_ext_get_data", gnutls_import.}
proc gnutls_ext_get_current_msg*(session: gnutls_session_t): cuint {.
    importc: "gnutls_ext_get_current_msg", gnutls_import.}
type
  gnutls_ext_recv_func* = proc (session: gnutls_session_t; data: ptr cuchar; len: csize): cint
  gnutls_ext_send_func* = proc (session: gnutls_session_t; extdata: gnutls_buffer_t): cint
  gnutls_ext_deinit_data_func* = proc (data: gnutls_ext_priv_data_t)
  gnutls_ext_pack_func* = proc (data: gnutls_ext_priv_data_t;
                             packed_data: gnutls_buffer_t): cint
  gnutls_ext_unpack_func* = proc (packed_data: gnutls_buffer_t;
                               data: ptr gnutls_ext_priv_data_t): cint

const
  GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO* = 1
  GNUTLS_EXT_RAW_FLAG_DTLS_CLIENT_HELLO* = (1 shl 1)

type
  gnutls_ext_raw_process_func* = proc (ctx: pointer; tls_id: cuint; data: ptr cuchar;
                                    data_size: cuint): cint

proc gnutls_ext_raw_parse*(ctx: pointer; cb: gnutls_ext_raw_process_func;
                          data: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_ext_raw_parse", gnutls_import.}
## *
##  gnutls_ext_parse_type_t:
##  @GNUTLS_EXT_NONE: Never to be parsed
##  @GNUTLS_EXT_ANY: Any extension type (should not be used as it is used only internally).
##  @GNUTLS_EXT_VERSION_NEG: Extensions to be parsed first for TLS version negotiation.
##  @GNUTLS_EXT_MANDATORY: Parsed after @GNUTLS_EXT_VERSION_NEG and even when resuming.
##  @GNUTLS_EXT_APPLICATION: Parsed after @GNUTLS_EXT_MANDATORY
##  @GNUTLS_EXT_TLS: TLS-internal extensions, parsed after @GNUTLS_EXT_APPLICATION.
##
##  Enumeration of different TLS extension parsing phases.  The @gnutls_ext_parse_type_t
##  indicates the time/phase an extension is parsed during Client or Server hello parsing.
##
##

type
  gnutls_ext_parse_type_t* {.size: sizeof(cint).} = enum
    GNUTLS_EXT_ANY = 0, GNUTLS_EXT_APPLICATION = 1, GNUTLS_EXT_TLS = 2,
    GNUTLS_EXT_MANDATORY = 3, GNUTLS_EXT_NONE = 4, GNUTLS_EXT_VERSION_NEG = 5


## *
##  gnutls_ext_flags_t:
##  @GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL: If specified the extension registered will override the internal; this does not work with extensions existing prior to 3.6.0.
##  @GNUTLS_EXT_FLAG_CLIENT_HELLO: This extension can be present in a client hello
##  @GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO: This extension can be present in a TLS1.2 or earlier server hello
##  @GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO: This extension can be present in a TLS1.3 server hello
##  @GNUTLS_EXT_FLAG_EE: This extension can be present in encrypted extensions message
##  @GNUTLS_EXT_FLAG_HRR: This extension can be present in hello retry request message
##  @GNUTLS_EXT_FLAG_IGNORE_CLIENT_REQUEST: When flag is present, this extension will be send even if the client didn't advertise it. An extension of this type is the Cookie TLS1.3 extension.
##  @GNUTLS_EXT_FLAG_DTLS: This extension can be present under DTLS; otherwise ignored.
##  @GNUTLS_EXT_FLAG_TLS: This extension can be present under TLS; otherwise ignored.
##
##  Enumeration of different TLS extension registration flags.
##

type
  gnutls_ext_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL = 1,
    GNUTLS_EXT_FLAG_CLIENT_HELLO = (1 shl 1),
    GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO = (1 shl 2),
    GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO = (1 shl 3), GNUTLS_EXT_FLAG_EE = (1 shl 4), ##  ENCRYPTED
    GNUTLS_EXT_FLAG_HRR = (1 shl 5),
    GNUTLS_EXT_FLAG_IGNORE_CLIENT_REQUEST = (1 shl 6),
    GNUTLS_EXT_FLAG_TLS = (1 shl 7), GNUTLS_EXT_FLAG_DTLS = (1 shl 8)


##  Register a custom tls extension
##

proc gnutls_ext_register*(name: cstring; `type`: cint;
                         parse_type: gnutls_ext_parse_type_t;
                         recv_func: gnutls_ext_recv_func;
                         send_func: gnutls_ext_send_func;
                         deinit_func: gnutls_ext_deinit_data_func;
                         pack_func: gnutls_ext_pack_func;
                         unpack_func: gnutls_ext_unpack_func): cint {.
    importc: "gnutls_ext_register", gnutls_import.}
proc gnutls_session_ext_register*(a1: gnutls_session_t; name: cstring; `type`: cint;
                                 parse_type: gnutls_ext_parse_type_t;
                                 recv_func: gnutls_ext_recv_func;
                                 send_func: gnutls_ext_send_func;
                                 deinit_func: gnutls_ext_deinit_data_func;
                                 pack_func: gnutls_ext_pack_func;
                                 unpack_func: gnutls_ext_unpack_func; flags: cuint): cint {.
    importc: "gnutls_session_ext_register", gnutls_import.}
proc gnutls_ext_get_name*(ext: cuint): cstring {.importc: "gnutls_ext_get_name",
    gnutls_import.}
##  Public supplemental data related functions

type
  gnutls_supp_recv_func* = proc (session: gnutls_session_t; data: ptr cuchar;
                              data_size: csize): cint
  gnutls_supp_send_func* = proc (session: gnutls_session_t; buf: gnutls_buffer_t): cint

proc gnutls_supplemental_register*(name: cstring; `type`: gnutls_supplemental_data_format_type_t;
                                  supp_recv_func: gnutls_supp_recv_func;
                                  supp_send_func: gnutls_supp_send_func): cint {.
    importc: "gnutls_supplemental_register", gnutls_import.}
proc gnutls_session_supplemental_register*(session: gnutls_session_t;
    name: cstring; `type`: gnutls_supplemental_data_format_type_t;
    supp_recv_func: gnutls_supp_recv_func; supp_send_func: gnutls_supp_send_func;
    flags: cuint): cint {.importc: "gnutls_session_supplemental_register",
                       gnutls_import.}
proc gnutls_supplemental_recv*(session: gnutls_session_t;
                              do_recv_supplemental: cuint) {.
    importc: "gnutls_supplemental_recv", gnutls_import.}
proc gnutls_supplemental_send*(session: gnutls_session_t;
                              do_send_supplemental: cuint) {.
    importc: "gnutls_supplemental_send", gnutls_import.}
##  Anti-replay related functions

type
  gnutls_anti_replay_st = object
  gnutls_anti_replay_t* = ptr gnutls_anti_replay_st

proc gnutls_anti_replay_init*(anti_replay: ptr gnutls_anti_replay_t): cint {.
    importc: "gnutls_anti_replay_init", gnutls_import.}
proc gnutls_anti_replay_deinit*(anti_replay: gnutls_anti_replay_t) {.
    importc: "gnutls_anti_replay_deinit", gnutls_import.}
proc gnutls_anti_replay_set_window*(anti_replay: gnutls_anti_replay_t;
                                   window: cuint) {.
    importc: "gnutls_anti_replay_set_window", gnutls_import.}
proc gnutls_anti_replay_enable*(session: gnutls_session_t;
                               anti_replay: gnutls_anti_replay_t) {.
    importc: "gnutls_anti_replay_enable", gnutls_import.}
type
  gnutls_db_add_func* = proc (a1: pointer; exp_time: time_t; key: ptr gnutls_datum_t;
                           data: ptr gnutls_datum_t): cint

proc gnutls_anti_replay_set_add_function*(a1: gnutls_anti_replay_t;
    add_func: gnutls_db_add_func) {.importc: "gnutls_anti_replay_set_add_function",
                                  gnutls_import.}
proc gnutls_anti_replay_set_ptr*(a1: gnutls_anti_replay_t; `ptr`: pointer) {.
    importc: "gnutls_anti_replay_set_ptr", gnutls_import.}
##  FIPS140-2 related functions

proc gnutls_fips140_mode_enabled*(): cuint {.
    importc: "gnutls_fips140_mode_enabled", gnutls_import.}
## *
##  gnutls_fips_mode_t:
##  @GNUTLS_FIPS140_DISABLED: The FIPS140-2 mode is disabled.
##  @GNUTLS_FIPS140_STRICT: The default mode; all forbidden operations will cause an
##                          operation failure via error code.
##  @GNUTLS_FIPS140_LAX: The library still uses the FIPS140-2 relevant algorithms but all
##                       forbidden by FIPS140-2 operations are allowed; this is useful when the
##                       application is aware of the followed security policy, and needs
##                       to utilize disallowed operations for other reasons (e.g., compatibility).
##  @GNUTLS_FIPS140_LOG: Similarly to %GNUTLS_FIPS140_LAX, it allows forbidden operations; any use of them results
##                       to a message to the audit callback functions.
##  @GNUTLS_FIPS140_SELFTESTS: A transient state during library initialization. That state
## 			cannot be set or seen by applications.
##
##  Enumeration of different operational modes under FIPS140-2.
##

type
  gnutls_fips_mode_t* {.size: sizeof(cint).} = enum
    GNUTLS_FIPS140_DISABLED = 0, GNUTLS_FIPS140_STRICT = 1,
    GNUTLS_FIPS140_SELFTESTS = 2, GNUTLS_FIPS140_LAX = 3, GNUTLS_FIPS140_LOG = 4


const
  GNUTLS_FIPS140_SET_MODE_THREAD* = 1

proc gnutls_fips140_set_mode*(mode: gnutls_fips_mode_t; flags: cuint) {.
    importc: "gnutls_fips140_set_mode", gnutls_import.}
template GNUTLS_FIPS140_SET_LAX_MODE*(): void =
  while true:
    if gnutls_fips140_mode_enabled():
      gnutls_fips140_set_mode(GNUTLS_FIPS140_LAX, GNUTLS_FIPS140_SET_MODE_THREAD)
    if not 0:
      break

template GNUTLS_FIPS140_SET_STRICT_MODE*(): void =
  while true:
    if gnutls_fips140_mode_enabled():
      gnutls_fips140_set_mode(GNUTLS_FIPS140_STRICT,
                              GNUTLS_FIPS140_SET_MODE_THREAD)
    if not 0:
      break

##  Gnutls error codes. The mapping to a TLS alert is also shown in
##  comments.
##

const
  GNUTLS_E_SUCCESS* = 0
  GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM* = -3
  GNUTLS_E_UNKNOWN_CIPHER_TYPE* = -6
  GNUTLS_E_LARGE_PACKET* = -7
  GNUTLS_E_UNSUPPORTED_VERSION_PACKET* = -8
  GNUTLS_E_UNEXPECTED_PACKET_LENGTH* = -9
  GNUTLS_E_TLS_PACKET_DECODING_ERROR* = GNUTLS_E_UNEXPECTED_PACKET_LENGTH
  GNUTLS_E_INVALID_SESSION* = -10
  GNUTLS_E_FATAL_ALERT_RECEIVED* = -12
  GNUTLS_E_UNEXPECTED_PACKET* = -15
  GNUTLS_E_WARNING_ALERT_RECEIVED* = -16
  GNUTLS_E_ERROR_IN_FINISHED_PACKET* = -18
  GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET* = -19
  GNUTLS_E_UNKNOWN_CIPHER_SUITE* = -21
  GNUTLS_E_UNWANTED_ALGORITHM* = -22
  GNUTLS_E_MPI_SCAN_FAILED* = -23
  GNUTLS_E_DECRYPTION_FAILED* = -24
  GNUTLS_E_MEMORY_ERROR* = -25
  GNUTLS_E_DECOMPRESSION_FAILED* = -26
  GNUTLS_E_COMPRESSION_FAILED* = -27
  GNUTLS_E_AGAIN* = -28
  GNUTLS_E_EXPIRED* = -29
  GNUTLS_E_DB_ERROR* = -30
  GNUTLS_E_KEYFILE_ERROR* = -31
  GNUTLS_E_SRP_PWD_ERROR* = GNUTLS_E_KEYFILE_ERROR
  GNUTLS_E_INSUFFICIENT_CREDENTIALS* = -32
  GNUTLS_E_INSUFICIENT_CREDENTIALS* = GNUTLS_E_INSUFFICIENT_CREDENTIALS
  GNUTLS_E_INSUFFICIENT_CRED* = GNUTLS_E_INSUFFICIENT_CREDENTIALS
  GNUTLS_E_INSUFICIENT_CRED* = GNUTLS_E_INSUFFICIENT_CREDENTIALS
  GNUTLS_E_HASH_FAILED* = -33
  GNUTLS_E_BASE64_DECODING_ERROR* = -34
  GNUTLS_E_MPI_PRINT_FAILED* = -35
  GNUTLS_E_REHANDSHAKE* = -37
  GNUTLS_E_GOT_APPLICATION_DATA* = -38
  GNUTLS_E_RECORD_LIMIT_REACHED* = -39
  GNUTLS_E_ENCRYPTION_FAILED* = -40
  GNUTLS_E_PK_ENCRYPTION_FAILED* = -44
  GNUTLS_E_PK_DECRYPTION_FAILED* = -45
  GNUTLS_E_PK_SIGN_FAILED* = -46
  GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION* = -47
  GNUTLS_E_KEY_USAGE_VIOLATION* = -48
  GNUTLS_E_NO_CERTIFICATE_FOUND* = -49
  GNUTLS_E_INVALID_REQUEST* = -50
  GNUTLS_E_SHORT_MEMORY_BUFFER* = -51
  GNUTLS_E_INTERRUPTED* = -52
  GNUTLS_E_PUSH_ERROR* = -53
  GNUTLS_E_PULL_ERROR* = -54
  GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER* = -55
  GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE* = -56
  GNUTLS_E_PKCS1_WRONG_PAD* = -57
  GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION* = -58
  GNUTLS_E_INTERNAL_ERROR* = -59
  GNUTLS_E_DH_PRIME_UNACCEPTABLE* = -63
  GNUTLS_E_FILE_ERROR* = -64
  GNUTLS_E_TOO_MANY_EMPTY_PACKETS* = -78
  GNUTLS_E_UNKNOWN_PK_ALGORITHM* = -80
  GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS* = -81

##  returned if you need to generate temporary RSA
##  parameters. These are needed for export cipher suites.
##

const
  GNUTLS_E_NO_TEMPORARY_RSA_PARAMS* = -84
  GNUTLS_E_NO_COMPRESSION_ALGORITHMS* = -86
  GNUTLS_E_NO_CIPHER_SUITES* = -87
  GNUTLS_E_OPENPGP_GETKEY_FAILED* = -88
  GNUTLS_E_PK_SIG_VERIFY_FAILED* = -89
  GNUTLS_E_ILLEGAL_SRP_USERNAME* = -90
  GNUTLS_E_KEYFILE_PARSING_ERROR* = -91
  GNUTLS_E_SRP_PWD_PARSING_ERROR* = GNUTLS_E_KEYFILE_PARSING_ERROR
  GNUTLS_E_NO_TEMPORARY_DH_PARAMS* = -93

##  For certificate and key stuff
##

const
  GNUTLS_E_ASN1_ELEMENT_NOT_FOUND* = -67
  GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND* = -68
  GNUTLS_E_ASN1_DER_ERROR* = -69
  GNUTLS_E_ASN1_VALUE_NOT_FOUND* = -70
  GNUTLS_E_ASN1_GENERIC_ERROR* = -71
  GNUTLS_E_ASN1_VALUE_NOT_VALID* = -72
  GNUTLS_E_ASN1_TAG_ERROR* = -73
  GNUTLS_E_ASN1_TAG_IMPLICIT* = -74
  GNUTLS_E_ASN1_TYPE_ANY_ERROR* = -75
  GNUTLS_E_ASN1_SYNTAX_ERROR* = -76
  GNUTLS_E_ASN1_DER_OVERFLOW* = -77
  GNUTLS_E_OPENPGP_UID_REVOKED* = -79
  GNUTLS_E_CERTIFICATE_ERROR* = -43
  GNUTLS_E_X509_CERTIFICATE_ERROR* = GNUTLS_E_CERTIFICATE_ERROR
  GNUTLS_E_CERTIFICATE_KEY_MISMATCH* = -60
  GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE* = -61
  GNUTLS_E_X509_UNKNOWN_SAN* = -62
  GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED* = -94
  GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE* = -95
  GNUTLS_E_UNKNOWN_HASH_ALGORITHM* = -96
  GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE* = -97
  GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE* = -98
  GNUTLS_E_INVALID_PASSWORD* = -99
  GNUTLS_E_MAC_VERIFY_FAILED* = -100
  GNUTLS_E_CONSTRAINT_ERROR* = -101
  GNUTLS_E_WARNING_IA_IPHF_RECEIVED* = -102
  GNUTLS_E_WARNING_IA_FPHF_RECEIVED* = -103
  GNUTLS_E_IA_VERIFY_FAILED* = -104
  GNUTLS_E_UNKNOWN_ALGORITHM* = -105
  GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM* = -106
  GNUTLS_E_SAFE_RENEGOTIATION_FAILED* = -107
  GNUTLS_E_UNSAFE_RENEGOTIATION_DENIED* = -108
  GNUTLS_E_UNKNOWN_SRP_USERNAME* = -109
  GNUTLS_E_PREMATURE_TERMINATION* = -110
  GNUTLS_E_MALFORMED_CIDR* = -111
  GNUTLS_E_BASE64_ENCODING_ERROR* = -201
  GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY* = -202
  GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY* = -202
  GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY* = -203
  GNUTLS_E_OPENPGP_KEYRING_ERROR* = -204
  GNUTLS_E_X509_UNSUPPORTED_OID* = -205
  GNUTLS_E_RANDOM_FAILED* = -206
  GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR* = -207
  GNUTLS_E_OPENPGP_SUBKEY_ERROR* = -208
  GNUTLS_E_ALREADY_REGISTERED* = -209
  GNUTLS_E_CRYPTO_ALREADY_REGISTERED* = GNUTLS_E_ALREADY_REGISTERED
  GNUTLS_E_HANDSHAKE_TOO_LARGE* = -210
  GNUTLS_E_CRYPTODEV_IOCTL_ERROR* = -211
  GNUTLS_E_CRYPTODEV_DEVICE_ERROR* = -212
  GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE* = -213
  GNUTLS_E_BAD_COOKIE* = -214
  GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR* = -215
  GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL* = -216
  GNUTLS_E_INSUFFICIENT_SECURITY* = -217
  GNUTLS_E_HEARTBEAT_PONG_RECEIVED* = -292
  GNUTLS_E_HEARTBEAT_PING_RECEIVED* = -293
  GNUTLS_E_UNRECOGNIZED_NAME* = -294

##  PKCS11 related

const
  GNUTLS_E_PKCS11_ERROR* = -300
  GNUTLS_E_PKCS11_LOAD_ERROR* = -301
  GNUTLS_E_PARSING_ERROR* = -302
  GNUTLS_E_PKCS11_PIN_ERROR* = -303
  GNUTLS_E_PKCS11_SLOT_ERROR* = -305
  GNUTLS_E_LOCKING_ERROR* = -306
  GNUTLS_E_PKCS11_ATTRIBUTE_ERROR* = -307
  GNUTLS_E_PKCS11_DEVICE_ERROR* = -308
  GNUTLS_E_PKCS11_DATA_ERROR* = -309
  GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR* = -310
  GNUTLS_E_PKCS11_KEY_ERROR* = -311
  GNUTLS_E_PKCS11_PIN_EXPIRED* = -312
  GNUTLS_E_PKCS11_PIN_LOCKED* = -313
  GNUTLS_E_PKCS11_SESSION_ERROR* = -314
  GNUTLS_E_PKCS11_SIGNATURE_ERROR* = -315
  GNUTLS_E_PKCS11_TOKEN_ERROR* = -316
  GNUTLS_E_PKCS11_USER_ERROR* = -317
  GNUTLS_E_CRYPTO_INIT_FAILED* = -318
  GNUTLS_E_TIMEDOUT* = -319
  GNUTLS_E_USER_ERROR* = -320
  GNUTLS_E_ECC_NO_SUPPORTED_CURVES* = -321
  GNUTLS_E_ECC_UNSUPPORTED_CURVE* = -322
  GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE* = -323
  GNUTLS_E_CERTIFICATE_LIST_UNSORTED* = -324
  GNUTLS_E_ILLEGAL_PARAMETER* = -325
  GNUTLS_E_NO_PRIORITIES_WERE_SET* = -326
  GNUTLS_E_X509_UNSUPPORTED_EXTENSION* = -327
  GNUTLS_E_SESSION_EOF* = -328
  GNUTLS_E_TPM_ERROR* = -329
  GNUTLS_E_TPM_KEY_PASSWORD_ERROR* = -330
  GNUTLS_E_TPM_SRK_PASSWORD_ERROR* = -331
  GNUTLS_E_TPM_SESSION_ERROR* = -332
  GNUTLS_E_TPM_KEY_NOT_FOUND* = -333
  GNUTLS_E_TPM_UNINITIALIZED* = -334
  GNUTLS_E_TPM_NO_LIB* = -335
  GNUTLS_E_NO_CERTIFICATE_STATUS* = -340
  GNUTLS_E_OCSP_RESPONSE_ERROR* = -341
  GNUTLS_E_RANDOM_DEVICE_ERROR* = -342
  GNUTLS_E_AUTH_ERROR* = -343
  GNUTLS_E_NO_APPLICATION_PROTOCOL* = -344
  GNUTLS_E_SOCKETS_INIT_ERROR* = -345
  GNUTLS_E_KEY_IMPORT_FAILED* = -346
  GNUTLS_E_INAPPROPRIATE_FALLBACK* = -347
  GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR* = -348
  GNUTLS_E_PRIVKEY_VERIFICATION_ERROR* = -349
  GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH* = -350
  GNUTLS_E_ASN1_EMBEDDED_NULL_IN_STRING* = -351
  GNUTLS_E_SELF_TEST_ERROR* = -400
  GNUTLS_E_NO_SELF_TEST* = -401
  GNUTLS_E_LIB_IN_ERROR_STATE* = -402
  GNUTLS_E_PK_GENERATION_ERROR* = -403
  GNUTLS_E_IDNA_ERROR* = -404
  GNUTLS_E_NEED_FALLBACK* = -405
  GNUTLS_E_SESSION_USER_ID_CHANGED* = -406
  GNUTLS_E_HANDSHAKE_DURING_FALSE_START* = -407
  GNUTLS_E_UNAVAILABLE_DURING_HANDSHAKE* = -408
  GNUTLS_E_PK_INVALID_PUBKEY* = -409
  GNUTLS_E_PK_INVALID_PRIVKEY* = -410
  GNUTLS_E_NOT_YET_ACTIVATED* = -411
  GNUTLS_E_INVALID_UTF8_STRING* = -412
  GNUTLS_E_NO_EMBEDDED_DATA* = -413
  GNUTLS_E_INVALID_UTF8_EMAIL* = -414
  GNUTLS_E_INVALID_PASSWORD_STRING* = -415
  GNUTLS_E_CERTIFICATE_TIME_ERROR* = -416
  GNUTLS_E_RECORD_OVERFLOW* = -417
  GNUTLS_E_ASN1_TIME_ERROR* = -418
  GNUTLS_E_INCOMPATIBLE_SIG_WITH_KEY* = -419
  GNUTLS_E_PK_INVALID_PUBKEY_PARAMS* = -420
  GNUTLS_E_PK_NO_VALIDATION_PARAMS* = -421
  GNUTLS_E_OCSP_MISMATCH_WITH_CERTS* = -422
  GNUTLS_E_NO_COMMON_KEY_SHARE* = -423
  GNUTLS_E_REAUTH_REQUEST* = -424
  GNUTLS_E_TOO_MANY_MATCHES* = -425
  GNUTLS_E_CRL_VERIFICATION_ERROR* = -426
  GNUTLS_E_MISSING_EXTENSION* = -427
  GNUTLS_E_DB_ENTRY_EXISTS* = -428
  GNUTLS_E_EARLY_DATA_REJECTED* = -429
  GNUTLS_E_UNIMPLEMENTED_FEATURE* = -1250

##  Internal errors of the library; will never be returned
##  to a calling application

const
  GNUTLS_E_INT_RET_0* = -1251
  GNUTLS_E_INT_CHECK_AGAIN* = -1252
  GNUTLS_E_APPLICATION_ERROR_MAX* = -65000
  GNUTLS_E_APPLICATION_ERROR_MIN* = -65500

##  *INDENT-OFF*

##  *INDENT-ON*
