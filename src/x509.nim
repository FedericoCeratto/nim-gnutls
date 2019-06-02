import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2003-2016 Free Software Foundation, Inc.
##  Copyright (C) 2015-2016 Red Hat, Inc.
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
##  Some OIDs usually found in Distinguished names, or
##  in Subject Directory Attribute extensions.
##

export gnutls_x509_privkey_t
const
  GNUTLS_OID_X520_COUNTRY_NAME* = "2.5.4.6"
  GNUTLS_OID_X520_ORGANIZATION_NAME* = "2.5.4.10"
  GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME* = "2.5.4.11"
  GNUTLS_OID_X520_COMMON_NAME* = "2.5.4.3"
  GNUTLS_OID_X520_LOCALITY_NAME* = "2.5.4.7"
  GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME* = "2.5.4.8"
  GNUTLS_OID_X520_INITIALS* = "2.5.4.43"
  GNUTLS_OID_X520_GENERATION_QUALIFIER* = "2.5.4.44"
  GNUTLS_OID_X520_SURNAME* = "2.5.4.4"
  GNUTLS_OID_X520_GIVEN_NAME* = "2.5.4.42"
  GNUTLS_OID_X520_TITLE* = "2.5.4.12"
  GNUTLS_OID_X520_DN_QUALIFIER* = "2.5.4.46"
  GNUTLS_OID_X520_PSEUDONYM* = "2.5.4.65"
  GNUTLS_OID_X520_POSTALCODE* = "2.5.4.17"
  GNUTLS_OID_X520_NAME* = "2.5.4.41"
  GNUTLS_OID_LDAP_DC* = "0.9.2342.19200300.100.1.25"
  GNUTLS_OID_LDAP_UID* = "0.9.2342.19200300.100.1.1"

##  The following should not be included in DN.
##

const
  GNUTLS_OID_PKCS9_EMAIL* = "1.2.840.113549.1.9.1"
  GNUTLS_OID_PKIX_DATE_OF_BIRTH* = "1.3.6.1.5.5.7.9.1"
  GNUTLS_OID_PKIX_PLACE_OF_BIRTH* = "1.3.6.1.5.5.7.9.2"
  GNUTLS_OID_PKIX_GENDER* = "1.3.6.1.5.5.7.9.3"
  GNUTLS_OID_PKIX_COUNTRY_OF_CITIZENSHIP* = "1.3.6.1.5.5.7.9.4"
  GNUTLS_OID_PKIX_COUNTRY_OF_RESIDENCE* = "1.3.6.1.5.5.7.9.5"

##  Key purpose Object Identifiers.
##

const
  GNUTLS_KP_TLS_WWW_SERVER* = "1.3.6.1.5.5.7.3.1"
  GNUTLS_KP_TLS_WWW_CLIENT* = "1.3.6.1.5.5.7.3.2"
  GNUTLS_KP_CODE_SIGNING* = "1.3.6.1.5.5.7.3.3"
  GNUTLS_KP_MS_SMART_CARD_LOGON* = "1.3.6.1.4.1.311.20.2.2"
  GNUTLS_KP_EMAIL_PROTECTION* = "1.3.6.1.5.5.7.3.4"
  GNUTLS_KP_TIME_STAMPING* = "1.3.6.1.5.5.7.3.8"
  GNUTLS_KP_OCSP_SIGNING* = "1.3.6.1.5.5.7.3.9"
  GNUTLS_KP_IPSEC_IKE* = "1.3.6.1.5.5.7.3.17"
  GNUTLS_KP_ANY* = "2.5.29.37.0"
  GNUTLS_KP_FLAG_DISALLOW_ANY* = 1
  GNUTLS_OID_AIA* = "1.3.6.1.5.5.7.1.1"
  GNUTLS_OID_AD_OCSP* = "1.3.6.1.5.5.7.48.1"
  GNUTLS_OID_AD_CAISSUERS* = "1.3.6.1.5.5.7.48.2"
  GNUTLS_FSAN_SET* = 0
  GNUTLS_FSAN_APPEND* = 1
  GNUTLS_FSAN_ENCODE_OCTET_STRING* = (1 shl 1)
  GNUTLS_FSAN_ENCODE_UTF8_STRING* = (1 shl 2)
  GNUTLS_X509EXT_OID_SUBJECT_KEY_ID* = "2.5.29.14"
  GNUTLS_X509EXT_OID_KEY_USAGE* = "2.5.29.15"
  GNUTLS_X509EXT_OID_PRIVATE_KEY_USAGE_PERIOD* = "2.5.29.16"
  GNUTLS_X509EXT_OID_SAN* = "2.5.29.17"
  GNUTLS_X509EXT_OID_IAN* = "2.5.29.18"
  GNUTLS_X509EXT_OID_BASIC_CONSTRAINTS* = "2.5.29.19"
  GNUTLS_X509EXT_OID_NAME_CONSTRAINTS* = "2.5.29.30"
  GNUTLS_X509EXT_OID_CRL_DIST_POINTS* = "2.5.29.31"
  GNUTLS_X509EXT_OID_CRT_POLICY* = "2.5.29.32"
  GNUTLS_X509EXT_OID_AUTHORITY_KEY_ID* = "2.5.29.35"
  GNUTLS_X509EXT_OID_EXTENDED_KEY_USAGE* = "2.5.29.37"
  GNUTLS_X509EXT_OID_INHIBIT_ANYPOLICY* = "2.5.29.52"
  GNUTLS_X509EXT_OID_AUTHORITY_INFO_ACCESS* = "1.3.6.1.5.5.7.1.1"
  GNUTLS_X509EXT_OID_PROXY_CRT_INFO* = "1.3.6.1.5.5.7.1.14"
  GNUTLS_X509EXT_OID_TLSFEATURES* = "1.3.6.1.5.5.7.1.24"
  GNUTLS_X509_OID_POLICY_ANY* = "2.5.29.54"

##  Certificate handling functions.
##
## *
##  gnutls_certificate_import_flags:
##  @GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED: Fail if the
##    certificates in the buffer are more than the space allocated for
##    certificates. The error code will be %GNUTLS_E_SHORT_MEMORY_BUFFER.
##  @GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED: Fail if the certificates
##    in the buffer are not ordered starting from subject to issuer.
##    The error code will be %GNUTLS_E_CERTIFICATE_LIST_UNSORTED.
##  @GNUTLS_X509_CRT_LIST_SORT: Sort the certificate chain if unsorted.
##
##  Enumeration of different certificate import flags.
##

type
  gnutls_certificate_import_flags* {.size: sizeof(cint).} = enum
    GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED = 1,
    GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED = 1 shl 1,
    GNUTLS_X509_CRT_LIST_SORT = 1 shl 2


proc gnutls_x509_crt_init*(cert: ptr gnutls_x509_crt_t): cint {.
    importc: "gnutls_x509_crt_init", gnutls_import.}
proc gnutls_x509_crt_deinit*(cert: gnutls_x509_crt_t) {.
    importc: "gnutls_x509_crt_deinit", gnutls_import.}
## *
##  gnutls_certificate_import_flags:
##  @GNUTLS_X509_CRT_FLAG_IGNORE_SANITY: Ignore any sanity checks at the
##    import of the certificate; i.e., ignore checks such as version/field
##    matching and strict time field checks. Intended to be used for debugging.
##
##  Enumeration of different certificate flags.
##

type
  gnutls_x509_crt_flags* {.size: sizeof(cint).} = enum
    GNUTLS_X509_CRT_FLAG_IGNORE_SANITY = 1


proc gnutls_x509_crt_set_flags*(cert: gnutls_x509_crt_t; flags: cuint) {.
    importc: "gnutls_x509_crt_set_flags", gnutls_import.}
proc gnutls_x509_crt_equals*(cert1: gnutls_x509_crt_t; cert2: gnutls_x509_crt_t): cuint {.
    importc: "gnutls_x509_crt_equals", gnutls_import.}
proc gnutls_x509_crt_equals2*(cert1: gnutls_x509_crt_t; der: ptr gnutls_datum_t): cuint {.
    importc: "gnutls_x509_crt_equals2", gnutls_import.}
proc gnutls_x509_crt_import*(cert: gnutls_x509_crt_t; data: ptr gnutls_datum_t;
                            format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_crt_import", gnutls_import.}
proc gnutls_x509_crt_list_import2*(certs: ptr ptr gnutls_x509_crt_t; size: ptr cuint;
                                  data: ptr gnutls_datum_t;
                                  format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_list_import2", gnutls_import.}
proc gnutls_x509_crt_list_import*(certs: ptr gnutls_x509_crt_t; cert_max: ptr cuint;
                                 data: ptr gnutls_datum_t;
                                 format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_list_import", gnutls_import.}
proc gnutls_x509_crt_import_url*(crt: gnutls_x509_crt_t; url: cstring; flags: cuint): cint {.
    importc: "gnutls_x509_crt_import_url", gnutls_import.}
  ##  GNUTLS_PKCS11_OBJ_FLAG_*
proc gnutls_x509_crt_list_import_url*(certs: ptr ptr gnutls_x509_crt_t;
                                     size: ptr cuint; url: cstring;
                                     pin_fn: gnutls_pin_callback_t;
                                     pin_fn_userdata: pointer; flags: cuint): cint {.
    importc: "gnutls_x509_crt_list_import_url", gnutls_import.}
proc gnutls_x509_crt_export*(cert: gnutls_x509_crt_t;
                            format: gnutls_x509_crt_fmt_t; output_data: pointer;
                            output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_export", gnutls_import.}
proc gnutls_x509_crt_export2*(cert: gnutls_x509_crt_t;
                             format: gnutls_x509_crt_fmt_t;
                             `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_export2", gnutls_import.}
proc gnutls_x509_crt_get_private_key_usage_period*(cert: gnutls_x509_crt_t;
    activation: ptr time_t; expiration: ptr time_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_private_key_usage_period", gnutls_import.}
proc gnutls_x509_crt_get_issuer_dn*(cert: gnutls_x509_crt_t; buf: cstring;
                                   buf_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_issuer_dn", gnutls_import.}
proc gnutls_x509_crt_get_issuer_dn2*(cert: gnutls_x509_crt_t;
                                    dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_issuer_dn2", gnutls_import.}
proc gnutls_x509_crt_get_issuer_dn3*(cert: gnutls_x509_crt_t;
                                    dn: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_get_issuer_dn3", gnutls_import.}
proc gnutls_x509_crt_get_issuer_dn_oid*(cert: gnutls_x509_crt_t; indx: cuint;
                                       oid: pointer; oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_issuer_dn_oid", gnutls_import.}
proc gnutls_x509_crt_get_issuer_dn_by_oid*(cert: gnutls_x509_crt_t; oid: cstring;
    indx: cuint; raw_flag: cuint; buf: pointer; buf_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_issuer_dn_by_oid", gnutls_import.}
proc gnutls_x509_crt_get_dn*(cert: gnutls_x509_crt_t; buf: cstring;
                            buf_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_dn", gnutls_import.}
proc gnutls_x509_crt_get_dn2*(cert: gnutls_x509_crt_t; dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_dn2", gnutls_import.}
proc gnutls_x509_crt_get_dn3*(cert: gnutls_x509_crt_t; dn: ptr gnutls_datum_t;
                             flags: cuint): cint {.
    importc: "gnutls_x509_crt_get_dn3", gnutls_import.}
proc gnutls_x509_crt_get_dn_oid*(cert: gnutls_x509_crt_t; indx: cuint; oid: pointer;
                                oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_dn_oid", gnutls_import.}
proc gnutls_x509_crt_get_dn_by_oid*(cert: gnutls_x509_crt_t; oid: cstring;
                                   indx: cuint; raw_flag: cuint; buf: pointer;
                                   buf_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_dn_by_oid", gnutls_import.}
proc gnutls_x509_crt_check_hostname*(cert: gnutls_x509_crt_t; hostname: cstring): cuint {.
    importc: "gnutls_x509_crt_check_hostname", gnutls_import.}
proc gnutls_x509_crt_check_hostname2*(cert: gnutls_x509_crt_t; hostname: cstring;
                                     flags: cuint): cuint {.
    importc: "gnutls_x509_crt_check_hostname2", gnutls_import.}
proc gnutls_x509_crt_check_email*(cert: gnutls_x509_crt_t; email: cstring;
                                 flags: cuint): cuint {.
    importc: "gnutls_x509_crt_check_email", gnutls_import.}
proc gnutls_x509_crt_check_ip*(cert: gnutls_x509_crt_t; ip: ptr cuchar;
                              ip_size: cuint; flags: cuint): cuint {.
    importc: "gnutls_x509_crt_check_ip", gnutls_import.}
proc gnutls_x509_crt_get_signature_algorithm*(cert: gnutls_x509_crt_t): cint {.
    importc: "gnutls_x509_crt_get_signature_algorithm", gnutls_import.}
proc gnutls_x509_crt_get_signature*(cert: gnutls_x509_crt_t; sig: cstring;
                                   sizeof_sig: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_signature", gnutls_import.}
proc gnutls_x509_crt_get_version*(cert: gnutls_x509_crt_t): cint {.
    importc: "gnutls_x509_crt_get_version", gnutls_import.}
proc gnutls_x509_crt_get_pk_oid*(cert: gnutls_x509_crt_t; oid: cstring;
                                oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_pk_oid", gnutls_import.}
proc gnutls_x509_crt_get_signature_oid*(cert: gnutls_x509_crt_t; oid: cstring;
                                       oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_signature_oid", gnutls_import.}
## *
##  gnutls_keyid_flags_t:
##  @GNUTLS_KEYID_USE_SHA1: Use SHA1 as the key ID algorithm (default).
##  @GNUTLS_KEYID_USE_SHA256: Use SHA256 as the key ID algorithm.
##  @GNUTLS_KEYID_USE_SHA512: Use SHA512 as the key ID algorithm.
##  @GNUTLS_KEYID_USE_BEST_KNOWN: Use the best known algorithm to calculate key ID. Using that option will make your program behavior depend on the version of gnutls linked with. That option has a cap of 64-bytes key IDs.
##
##  Enumeration of different flags for the key ID functions.
##
##

type
  gnutls_keyid_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_KEYID_USE_SHA1 = 0, GNUTLS_KEYID_USE_SHA256 = (1 shl 0),
    GNUTLS_KEYID_USE_SHA512 = (1 shl 1), GNUTLS_KEYID_USE_BEST_KNOWN = (1 shl 30)


proc gnutls_x509_crt_get_key_id*(crt: gnutls_x509_crt_t; flags: cuint;
                                output_data: ptr cuchar;
                                output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_key_id", gnutls_import.}
proc gnutls_x509_crt_set_private_key_usage_period*(crt: gnutls_x509_crt_t;
    activation: time_t; expiration: time_t): cint {.
    importc: "gnutls_x509_crt_set_private_key_usage_period", gnutls_import.}
proc gnutls_x509_crt_set_authority_key_id*(cert: gnutls_x509_crt_t; id: pointer;
    id_size: csize): cint {.importc: "gnutls_x509_crt_set_authority_key_id",
                         gnutls_import.}
proc gnutls_x509_crt_get_authority_key_id*(cert: gnutls_x509_crt_t; id: pointer;
    id_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_authority_key_id", gnutls_import.}
proc gnutls_x509_crt_get_authority_key_gn_serial*(cert: gnutls_x509_crt_t;
    seq: cuint; alt: pointer; alt_size: ptr csize; alt_type: ptr cuint; serial: pointer;
    serial_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_authority_key_gn_serial", gnutls_import.}
proc gnutls_x509_crt_get_subject_key_id*(cert: gnutls_x509_crt_t; ret: pointer;
                                        ret_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_subject_key_id", gnutls_import.}
proc gnutls_x509_crt_get_subject_unique_id*(crt: gnutls_x509_crt_t; buf: cstring;
    buf_size: ptr csize): cint {.importc: "gnutls_x509_crt_get_subject_unique_id",
                             gnutls_import.}
proc gnutls_x509_crt_get_issuer_unique_id*(crt: gnutls_x509_crt_t; buf: cstring;
    buf_size: ptr csize): cint {.importc: "gnutls_x509_crt_get_issuer_unique_id",
                             gnutls_import.}
proc gnutls_x509_crt_set_pin_function*(crt: gnutls_x509_crt_t;
                                      fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_x509_crt_set_pin_function", gnutls_import.}
## *
##  gnutls_info_access_what_t:
##  @GNUTLS_IA_ACCESSMETHOD_OID: Get accessMethod OID.
##  @GNUTLS_IA_ACCESSLOCATION_GENERALNAME_TYPE: Get accessLocation name type.
##  @GNUTLS_IA_URI: Get accessLocation URI value.
##  @GNUTLS_IA_OCSP_URI: get accessLocation URI value for OCSP.
##  @GNUTLS_IA_CAISSUERS_URI: get accessLocation URI value for caIssuers.
##
##  Enumeration of types for the @what parameter of
##  gnutls_x509_crt_get_authority_info_access().
##

type
  gnutls_info_access_what_t* {.size: sizeof(cint).} = enum
    GNUTLS_IA_ACCESSMETHOD_OID = 1, GNUTLS_IA_ACCESSLOCATION_GENERALNAME_TYPE = 2, ##  use 100-108 for the generalName types, populate as needed
    GNUTLS_IA_URI = 106,        ##  quick-access variants that match both OID and name type.
    GNUTLS_IA_UNKNOWN = 10000, GNUTLS_IA_OCSP_URI = 10006,
    GNUTLS_IA_CAISSUERS_URI = 10106


proc gnutls_x509_crt_get_authority_info_access*(crt: gnutls_x509_crt_t; seq: cuint;
    what: cint; data: ptr gnutls_datum_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_authority_info_access", gnutls_import.}
type
  gnutls_name_constraints_st {.bycopy.} = object
  gnutls_x509_name_constraints_t* = ptr gnutls_name_constraints_st

proc gnutls_x509_name_constraints_check*(nc: gnutls_x509_name_constraints_t;
                                        `type`: gnutls_x509_subject_alt_name_t;
                                        name: ptr gnutls_datum_t): cuint {.
    importc: "gnutls_x509_name_constraints_check", gnutls_import.}
proc gnutls_x509_name_constraints_check_crt*(nc: gnutls_x509_name_constraints_t;
    `type`: gnutls_x509_subject_alt_name_t; crt: gnutls_x509_crt_t): cuint {.
    importc: "gnutls_x509_name_constraints_check_crt", gnutls_import.}
proc gnutls_x509_name_constraints_init*(nc: ptr gnutls_x509_name_constraints_t): cint {.
    importc: "gnutls_x509_name_constraints_init", gnutls_import.}
proc gnutls_x509_name_constraints_deinit*(nc: gnutls_x509_name_constraints_t) {.
    importc: "gnutls_x509_name_constraints_deinit", gnutls_import.}
const
  GNUTLS_EXT_FLAG_APPEND* = 1
  GNUTLS_NAME_CONSTRAINTS_FLAG_APPEND* = GNUTLS_EXT_FLAG_APPEND

proc gnutls_x509_crt_get_name_constraints*(crt: gnutls_x509_crt_t;
    nc: gnutls_x509_name_constraints_t; flags: cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_name_constraints", gnutls_import.}
proc gnutls_x509_name_constraints_add_permitted*(
    nc: gnutls_x509_name_constraints_t; `type`: gnutls_x509_subject_alt_name_t;
    name: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_name_constraints_add_permitted",
                                  gnutls_import.}
proc gnutls_x509_name_constraints_add_excluded*(
    nc: gnutls_x509_name_constraints_t; `type`: gnutls_x509_subject_alt_name_t;
    name: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_name_constraints_add_excluded",
                                  gnutls_import.}
proc gnutls_x509_crt_set_name_constraints*(crt: gnutls_x509_crt_t;
    nc: gnutls_x509_name_constraints_t; critical: cuint): cint {.
    importc: "gnutls_x509_crt_set_name_constraints", gnutls_import.}
proc gnutls_x509_name_constraints_get_permitted*(
    nc: gnutls_x509_name_constraints_t; idx: cuint; `type`: ptr cuint;
    name: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_name_constraints_get_permitted",
                                  gnutls_import.}
proc gnutls_x509_name_constraints_get_excluded*(
    nc: gnutls_x509_name_constraints_t; idx: cuint; `type`: ptr cuint;
    name: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_name_constraints_get_excluded",
                                  gnutls_import.}
proc gnutls_x509_cidr_to_rfc5280*(cidr: cstring; cidr_rfc5280: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_cidr_to_rfc5280", gnutls_import.}
## #define GNUTLS_CRL_REASON_SUPERSEEDED GNUTLS_CRL_REASON_SUPERSEDED,
## *
##  gnutls_x509_crl_reason_flags_t:
##  @GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN: The privileges were withdrawn from the owner.
##  @GNUTLS_CRL_REASON_CERTIFICATE_HOLD: The certificate is on hold.
##  @GNUTLS_CRL_REASON_CESSATION_OF_OPERATION: The end-entity is no longer operating.
##  @GNUTLS_CRL_REASON_SUPERSEDED: There is a newer certificate of the owner.
##  @GNUTLS_CRL_REASON_AFFILIATION_CHANGED: The end-entity affiliation has changed.
##  @GNUTLS_CRL_REASON_CA_COMPROMISE: The CA was compromised.
##  @GNUTLS_CRL_REASON_KEY_COMPROMISE: The certificate's key was compromised.
##  @GNUTLS_CRL_REASON_UNUSED: The key was never used.
##  @GNUTLS_CRL_REASON_AA_COMPROMISE: AA compromised.
##
##  Enumeration of types for the CRL revocation reasons.
##

type
  gnutls_x509_crl_reason_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_CRL_REASON_UNSPECIFIED = 0, GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN = 1,
    GNUTLS_CRL_REASON_CERTIFICATE_HOLD = 2,
    GNUTLS_CRL_REASON_CESSATION_OF_OPERATION = 4, GNUTLS_CRL_REASON_SUPERSEDED = 8,
    GNUTLS_CRL_REASON_AFFILIATION_CHANGED = 16,
    GNUTLS_CRL_REASON_CA_COMPROMISE = 32, GNUTLS_CRL_REASON_KEY_COMPROMISE = 64,
    GNUTLS_CRL_REASON_UNUSED = 128, GNUTLS_CRL_REASON_AA_COMPROMISE = 32768


proc gnutls_x509_crt_get_crl_dist_points*(cert: gnutls_x509_crt_t; seq: cuint;
    ret: pointer; ret_size: ptr csize; reason_flags: ptr cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_crl_dist_points", gnutls_import.}
proc gnutls_x509_crt_set_crl_dist_points2*(crt: gnutls_x509_crt_t;
    `type`: gnutls_x509_subject_alt_name_t; data: pointer; data_size: cuint;
    reason_flags: cuint): cint {.importc: "gnutls_x509_crt_set_crl_dist_points2",
                              gnutls_import.}
proc gnutls_x509_crt_set_crl_dist_points*(crt: gnutls_x509_crt_t;
    `type`: gnutls_x509_subject_alt_name_t; data_string: pointer;
    reason_flags: cuint): cint {.importc: "gnutls_x509_crt_set_crl_dist_points",
                              gnutls_import.}
proc gnutls_x509_crt_cpy_crl_dist_points*(dst: gnutls_x509_crt_t;
    src: gnutls_x509_crt_t): cint {.importc: "gnutls_x509_crt_cpy_crl_dist_points",
                                 gnutls_import.}
proc gnutls_x509_crl_sign*(crl: gnutls_x509_crl_t; issuer: gnutls_x509_crt_t;
                          issuer_key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_crl_sign", gnutls_import.}
proc gnutls_x509_crl_sign2*(crl: gnutls_x509_crl_t; issuer: gnutls_x509_crt_t;
                           issuer_key: gnutls_x509_privkey_t;
                           dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crl_sign2", gnutls_import.}
proc gnutls_x509_crt_get_activation_time*(cert: gnutls_x509_crt_t): time_t {.
    importc: "gnutls_x509_crt_get_activation_time", gnutls_import.}
##  This macro is deprecated and defunc; do not use
##  #define GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION ((time_t)4294197631)

proc gnutls_x509_crt_get_expiration_time*(cert: gnutls_x509_crt_t): time_t {.
    importc: "gnutls_x509_crt_get_expiration_time", gnutls_import.}
proc gnutls_x509_crt_get_serial*(cert: gnutls_x509_crt_t; result: pointer;
                                result_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_serial", gnutls_import.}
type
  gnutls_x509_spki_st = object
  gnutls_x509_spki_t* = ptr gnutls_x509_spki_st

proc gnutls_x509_spki_init*(spki: ptr gnutls_x509_spki_t): cint {.
    importc: "gnutls_x509_spki_init", gnutls_import.}
proc gnutls_x509_spki_deinit*(spki: gnutls_x509_spki_t) {.
    importc: "gnutls_x509_spki_deinit", gnutls_import.}
proc gnutls_x509_spki_get_rsa_pss_params*(spki: gnutls_x509_spki_t;
    dig: ptr gnutls_digest_algorithm_t; salt_size: ptr cuint): cint {.
    importc: "gnutls_x509_spki_get_rsa_pss_params", gnutls_import.}
proc gnutls_x509_spki_set_rsa_pss_params*(spki: gnutls_x509_spki_t;
    dig: gnutls_digest_algorithm_t; salt_size: cuint) {.
    importc: "gnutls_x509_spki_set_rsa_pss_params", gnutls_import.}
proc gnutls_x509_crt_get_pk_algorithm*(cert: gnutls_x509_crt_t; bits: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_pk_algorithm", gnutls_import.}
proc gnutls_x509_crt_set_spki*(crt: gnutls_x509_crt_t; spki: gnutls_x509_spki_t;
                              flags: cuint): cint {.
    importc: "gnutls_x509_crt_set_spki", gnutls_import.}
proc gnutls_x509_crt_get_spki*(cert: gnutls_x509_crt_t; spki: gnutls_x509_spki_t;
                              flags: cuint): cint {.
    importc: "gnutls_x509_crt_get_spki", gnutls_import.}
proc gnutls_x509_crt_get_pk_rsa_raw*(crt: gnutls_x509_crt_t; m: ptr gnutls_datum_t;
                                    e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_pk_rsa_raw", gnutls_import.}
proc gnutls_x509_crt_get_pk_dsa_raw*(crt: gnutls_x509_crt_t; p: ptr gnutls_datum_t;
                                    q: ptr gnutls_datum_t; g: ptr gnutls_datum_t;
                                    y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_pk_dsa_raw", gnutls_import.}
proc gnutls_x509_crt_get_pk_ecc_raw*(crt: gnutls_x509_crt_t;
                                    curve: ptr gnutls_ecc_curve_t;
                                    x: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_pk_ecc_raw", gnutls_import.}
proc gnutls_x509_crt_get_pk_gost_raw*(crt: gnutls_x509_crt_t;
                                     curve: ptr gnutls_ecc_curve_t;
                                     digest: ptr gnutls_digest_algorithm_t;
                                     paramset: ptr gnutls_gost_paramset_t;
                                     x: ptr gnutls_datum_t; y: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_pk_gost_raw", gnutls_import.}
proc gnutls_x509_crt_get_subject_alt_name*(cert: gnutls_x509_crt_t; seq: cuint;
    san: pointer; san_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_subject_alt_name", gnutls_import.}
proc gnutls_x509_crt_get_subject_alt_name2*(cert: gnutls_x509_crt_t; seq: cuint;
    san: pointer; san_size: ptr csize; san_type: ptr cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_subject_alt_name2", gnutls_import.}
proc gnutls_x509_crt_get_subject_alt_othername_oid*(cert: gnutls_x509_crt_t;
    seq: cuint; oid: pointer; oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_subject_alt_othername_oid", gnutls_import.}
proc gnutls_x509_crt_get_issuer_alt_name*(cert: gnutls_x509_crt_t; seq: cuint;
    ian: pointer; ian_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_issuer_alt_name", gnutls_import.}
proc gnutls_x509_crt_get_issuer_alt_name2*(cert: gnutls_x509_crt_t; seq: cuint;
    ian: pointer; ian_size: ptr csize; ian_type: ptr cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_issuer_alt_name2", gnutls_import.}
proc gnutls_x509_crt_get_issuer_alt_othername_oid*(cert: gnutls_x509_crt_t;
    seq: cuint; ret: pointer; ret_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_issuer_alt_othername_oid", gnutls_import.}
proc gnutls_x509_crt_get_ca_status*(cert: gnutls_x509_crt_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_ca_status", gnutls_import.}
proc gnutls_x509_crt_get_basic_constraints*(cert: gnutls_x509_crt_t;
    critical: ptr cuint; ca: ptr cuint; pathlen: ptr cint): cint {.
    importc: "gnutls_x509_crt_get_basic_constraints", gnutls_import.}
##  The key_usage flags are defined in gnutls.h. They are the
##  GNUTLS_KEY_* definitions.
##

proc gnutls_x509_crt_get_key_usage*(cert: gnutls_x509_crt_t; key_usage: ptr cuint;
                                   critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_key_usage", gnutls_import.}
proc gnutls_x509_crt_set_key_usage*(crt: gnutls_x509_crt_t; usage: cuint): cint {.
    importc: "gnutls_x509_crt_set_key_usage", gnutls_import.}
proc gnutls_x509_crt_set_authority_info_access*(crt: gnutls_x509_crt_t; what: cint;
    data: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_crt_set_authority_info_access",
                                  gnutls_import.}
proc gnutls_x509_crt_get_inhibit_anypolicy*(cert: gnutls_x509_crt_t;
    skipcerts: ptr cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_inhibit_anypolicy", gnutls_import.}
proc gnutls_x509_crt_set_inhibit_anypolicy*(crt: gnutls_x509_crt_t;
    skipcerts: cuint): cint {.importc: "gnutls_x509_crt_set_inhibit_anypolicy",
                           gnutls_import.}
proc gnutls_x509_crt_get_proxy*(cert: gnutls_x509_crt_t; critical: ptr cuint;
                               pathlen: ptr cint; policyLanguage: cstringArray;
                               policy: cstringArray; sizeof_policy: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_proxy", gnutls_import.}
type
  gnutls_x509_tlsfeatures_st = object
  gnutls_x509_tlsfeatures_t* = ptr gnutls_x509_tlsfeatures_st

proc gnutls_x509_tlsfeatures_init*(features: ptr gnutls_x509_tlsfeatures_t): cint {.
    importc: "gnutls_x509_tlsfeatures_init", gnutls_import.}
proc gnutls_x509_tlsfeatures_deinit*(a1: gnutls_x509_tlsfeatures_t) {.
    importc: "gnutls_x509_tlsfeatures_deinit", gnutls_import.}
proc gnutls_x509_tlsfeatures_get*(f: gnutls_x509_tlsfeatures_t; idx: cuint;
                                 feature: ptr cuint): cint {.
    importc: "gnutls_x509_tlsfeatures_get", gnutls_import.}
proc gnutls_x509_crt_set_tlsfeatures*(crt: gnutls_x509_crt_t;
                                     features: gnutls_x509_tlsfeatures_t): cint {.
    importc: "gnutls_x509_crt_set_tlsfeatures", gnutls_import.}
proc gnutls_x509_crt_get_tlsfeatures*(cert: gnutls_x509_crt_t;
                                     features: gnutls_x509_tlsfeatures_t;
                                     flags: cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_tlsfeatures", gnutls_import.}
proc gnutls_x509_tlsfeatures_check_crt*(feat: gnutls_x509_tlsfeatures_t;
                                       crt: gnutls_x509_crt_t): cuint {.
    importc: "gnutls_x509_tlsfeatures_check_crt", gnutls_import.}
const
  GNUTLS_MAX_QUALIFIERS* = 8

## *
##  gnutls_x509_qualifier_t:
##  @GNUTLS_X509_QUALIFIER_UNKNOWN: Unknown qualifier.
##  @GNUTLS_X509_QUALIFIER_URI: A URL
##  @GNUTLS_X509_QUALIFIER_NOICE: A text notice.
##
##  Enumeration of types for the X.509 qualifiers, of the certificate policy extension.
##

type
  INNER_C_STRUCT_x509_569* {.bycopy.} = object
    `type`*: gnutls_x509_qualifier_t
    data*: cstring
    size*: cuint

  gnutls_x509_qualifier_t* {.size: sizeof(cint).} = enum
    GNUTLS_X509_QUALIFIER_UNKNOWN = 0, GNUTLS_X509_QUALIFIER_URI,
    GNUTLS_X509_QUALIFIER_NOTICE
  gnutls_x509_policy_st* {.bycopy.} = object
    oid*: cstring
    qualifiers*: cuint
    qualifier*: array[GNUTLS_MAX_QUALIFIERS, INNER_C_STRUCT_x509_569]



proc gnutls_x509_policy_release*(policy: ptr gnutls_x509_policy_st) {.
    importc: "gnutls_x509_policy_release", gnutls_import.}
proc gnutls_x509_crt_get_policy*(crt: gnutls_x509_crt_t; indx: cuint;
                                policy: ptr gnutls_x509_policy_st;
                                critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_policy", gnutls_import.}
proc gnutls_x509_crt_set_policy*(crt: gnutls_x509_crt_t;
                                policy: ptr gnutls_x509_policy_st; critical: cuint): cint {.
    importc: "gnutls_x509_crt_set_policy", gnutls_import.}
proc gnutls_x509_dn_oid_known*(oid: cstring): cint {.
    importc: "gnutls_x509_dn_oid_known", gnutls_import.}
const
  GNUTLS_X509_DN_OID_RETURN_OID* = 1

proc gnutls_x509_dn_oid_name*(oid: cstring; flags: cuint): cstring {.
    importc: "gnutls_x509_dn_oid_name", gnutls_import.}
##  Read extensions by OID.

proc gnutls_x509_crt_get_extension_oid*(cert: gnutls_x509_crt_t; indx: cuint;
                                       oid: pointer; oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_extension_oid", gnutls_import.}
proc gnutls_x509_crt_get_extension_by_oid*(cert: gnutls_x509_crt_t; oid: cstring;
    indx: cuint; buf: pointer; buf_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_extension_by_oid", gnutls_import.}
proc gnutls_x509_crq_get_signature_algorithm*(crq: gnutls_x509_crq_t): cint {.
    importc: "gnutls_x509_crq_get_signature_algorithm", gnutls_import.}
proc gnutls_x509_crq_get_extension_by_oid2*(crq: gnutls_x509_crq_t; oid: cstring;
    indx: cuint; output: ptr gnutls_datum_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_extension_by_oid2", gnutls_import.}
##  Read extensions by sequence number.

proc gnutls_x509_crt_get_extension_info*(cert: gnutls_x509_crt_t; indx: cuint;
                                        oid: pointer; oid_size: ptr csize;
                                        critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_extension_info", gnutls_import.}
proc gnutls_x509_crt_get_extension_data*(cert: gnutls_x509_crt_t; indx: cuint;
                                        data: pointer; sizeof_data: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_extension_data", gnutls_import.}
proc gnutls_x509_crt_get_extension_data2*(cert: gnutls_x509_crt_t; indx: cuint;
    data: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_crt_get_extension_data2",
                                  gnutls_import.}
proc gnutls_x509_crt_set_extension_by_oid*(crt: gnutls_x509_crt_t; oid: cstring;
    buf: pointer; sizeof_buf: csize; critical: cuint): cint {.
    importc: "gnutls_x509_crt_set_extension_by_oid", gnutls_import.}
##  X.509 Certificate writing.
##

proc gnutls_x509_crt_set_dn*(crt: gnutls_x509_crt_t; dn: cstring; err: cstringArray): cint {.
    importc: "gnutls_x509_crt_set_dn", gnutls_import.}
proc gnutls_x509_crt_set_dn_by_oid*(crt: gnutls_x509_crt_t; oid: cstring;
                                   raw_flag: cuint; name: pointer;
                                   sizeof_name: cuint): cint {.
    importc: "gnutls_x509_crt_set_dn_by_oid", gnutls_import.}
proc gnutls_x509_crt_set_issuer_dn_by_oid*(crt: gnutls_x509_crt_t; oid: cstring;
    raw_flag: cuint; name: pointer; sizeof_name: cuint): cint {.
    importc: "gnutls_x509_crt_set_issuer_dn_by_oid", gnutls_import.}
proc gnutls_x509_crt_set_issuer_dn*(crt: gnutls_x509_crt_t; dn: cstring;
                                   err: cstringArray): cint {.
    importc: "gnutls_x509_crt_set_issuer_dn", gnutls_import.}
proc gnutls_x509_crt_set_version*(crt: gnutls_x509_crt_t; version: cuint): cint {.
    importc: "gnutls_x509_crt_set_version", gnutls_import.}
proc gnutls_x509_crt_set_key*(crt: gnutls_x509_crt_t; key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_crt_set_key", gnutls_import.}
proc gnutls_x509_crt_set_ca_status*(crt: gnutls_x509_crt_t; ca: cuint): cint {.
    importc: "gnutls_x509_crt_set_ca_status", gnutls_import.}
proc gnutls_x509_crt_set_basic_constraints*(crt: gnutls_x509_crt_t; ca: cuint;
    pathLenConstraint: cint): cint {.importc: "gnutls_x509_crt_set_basic_constraints",
                                  gnutls_import.}
proc gnutls_x509_crt_set_subject_unique_id*(cert: gnutls_x509_crt_t; id: pointer;
    id_size: csize): cint {.importc: "gnutls_x509_crt_set_subject_unique_id",
                         gnutls_import.}
proc gnutls_x509_crt_set_issuer_unique_id*(cert: gnutls_x509_crt_t; id: pointer;
    id_size: csize): cint {.importc: "gnutls_x509_crt_set_issuer_unique_id",
                         gnutls_import.}
proc gnutls_x509_crt_set_subject_alternative_name*(crt: gnutls_x509_crt_t;
    `type`: gnutls_x509_subject_alt_name_t; data_string: cstring): cint {.
    importc: "gnutls_x509_crt_set_subject_alternative_name", gnutls_import.}
proc gnutls_x509_crt_set_subject_alt_name*(crt: gnutls_x509_crt_t;
    `type`: gnutls_x509_subject_alt_name_t; data: pointer; data_size: cuint;
    flags: cuint): cint {.importc: "gnutls_x509_crt_set_subject_alt_name",
                       gnutls_import.}
proc gnutls_x509_crt_set_subject_alt_othername*(crt: gnutls_x509_crt_t;
    oid: cstring; data: pointer; data_size: cuint; flags: cuint): cint {.
    importc: "gnutls_x509_crt_set_subject_alt_othername", gnutls_import.}
proc gnutls_x509_crt_set_issuer_alt_name*(crt: gnutls_x509_crt_t;
    `type`: gnutls_x509_subject_alt_name_t; data: pointer; data_size: cuint;
    flags: cuint): cint {.importc: "gnutls_x509_crt_set_issuer_alt_name", gnutls_import.}
proc gnutls_x509_crt_set_issuer_alt_othername*(crt: gnutls_x509_crt_t;
    oid: cstring; data: pointer; data_size: cuint; flags: cuint): cint {.
    importc: "gnutls_x509_crt_set_issuer_alt_othername", gnutls_import.}
proc gnutls_x509_crt_sign*(crt: gnutls_x509_crt_t; issuer: gnutls_x509_crt_t;
                          issuer_key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_crt_sign", gnutls_import.}
proc gnutls_x509_crt_sign2*(crt: gnutls_x509_crt_t; issuer: gnutls_x509_crt_t;
                           issuer_key: gnutls_x509_privkey_t;
                           dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crt_sign2", gnutls_import.}
proc gnutls_x509_crt_set_activation_time*(cert: gnutls_x509_crt_t; act_time: time_t): cint {.
    importc: "gnutls_x509_crt_set_activation_time", gnutls_import.}
proc gnutls_x509_crt_set_expiration_time*(cert: gnutls_x509_crt_t; exp_time: time_t): cint {.
    importc: "gnutls_x509_crt_set_expiration_time", gnutls_import.}
proc gnutls_x509_crt_set_serial*(cert: gnutls_x509_crt_t; serial: pointer;
                                serial_size: csize): cint {.
    importc: "gnutls_x509_crt_set_serial", gnutls_import.}
proc gnutls_x509_crt_set_subject_key_id*(cert: gnutls_x509_crt_t; id: pointer;
                                        id_size: csize): cint {.
    importc: "gnutls_x509_crt_set_subject_key_id", gnutls_import.}
proc gnutls_x509_crt_set_proxy_dn*(crt: gnutls_x509_crt_t;
                                  eecrt: gnutls_x509_crt_t; raw_flag: cuint;
                                  name: pointer; sizeof_name: cuint): cint {.
    importc: "gnutls_x509_crt_set_proxy_dn", gnutls_import.}
proc gnutls_x509_crt_set_proxy*(crt: gnutls_x509_crt_t; pathLenConstraint: cint;
                               policyLanguage: cstring; policy: cstring;
                               sizeof_policy: csize): cint {.
    importc: "gnutls_x509_crt_set_proxy", gnutls_import.}
proc gnutls_x509_crt_print*(cert: gnutls_x509_crt_t;
                           format: gnutls_certificate_print_formats_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_print", gnutls_import.}
proc gnutls_x509_crl_print*(crl: gnutls_x509_crl_t;
                           format: gnutls_certificate_print_formats_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crl_print", gnutls_import.}
##  Access to internal Certificate fields.
##

proc gnutls_x509_crt_get_raw_issuer_dn*(cert: gnutls_x509_crt_t;
                                       start: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_raw_issuer_dn", gnutls_import.}
proc gnutls_x509_crt_get_raw_dn*(cert: gnutls_x509_crt_t; start: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_get_raw_dn", gnutls_import.}
##  RDN handling.
##

proc gnutls_x509_rdn_get*(idn: ptr gnutls_datum_t; buf: cstring; sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_rdn_get", gnutls_import.}
proc gnutls_x509_rdn_get2*(idn: ptr gnutls_datum_t; str: ptr gnutls_datum_t;
                          flags: cuint): cint {.importc: "gnutls_x509_rdn_get2",
    gnutls_import.}
proc gnutls_x509_rdn_get_oid*(idn: ptr gnutls_datum_t; indx: cuint; buf: pointer;
                             sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_rdn_get_oid", gnutls_import.}
proc gnutls_x509_rdn_get_by_oid*(idn: ptr gnutls_datum_t; oid: cstring; indx: cuint;
                                raw_flag: cuint; buf: pointer; sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_rdn_get_by_oid", gnutls_import.}
type
  gnutls_x509_dn_st = object
  gnutls_x509_dn_t* = ptr gnutls_x509_dn_st
  gnutls_x509_ava_st* {.bycopy.} = object
    oid*: gnutls_datum_t
    value*: gnutls_datum_t
    value_tag*: culong


proc gnutls_x509_crt_get_subject*(cert: gnutls_x509_crt_t; dn: ptr gnutls_x509_dn_t): cint {.
    importc: "gnutls_x509_crt_get_subject", gnutls_import.}
proc gnutls_x509_crt_get_issuer*(cert: gnutls_x509_crt_t; dn: ptr gnutls_x509_dn_t): cint {.
    importc: "gnutls_x509_crt_get_issuer", gnutls_import.}
proc gnutls_x509_dn_get_rdn_ava*(dn: gnutls_x509_dn_t; irdn: cint; iava: cint;
                                ava: ptr gnutls_x509_ava_st): cint {.
    importc: "gnutls_x509_dn_get_rdn_ava", gnutls_import.}
proc gnutls_x509_dn_get_str*(dn: gnutls_x509_dn_t; str: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_dn_get_str", gnutls_import.}
const
  GNUTLS_X509_DN_FLAG_COMPAT* = 1

proc gnutls_x509_dn_get_str2*(dn: gnutls_x509_dn_t; str: ptr gnutls_datum_t;
                             flags: cuint): cint {.
    importc: "gnutls_x509_dn_get_str2", gnutls_import.}
proc gnutls_x509_dn_set_str*(dn: gnutls_x509_dn_t; str: cstring; err: cstringArray): cint {.
    importc: "gnutls_x509_dn_set_str", gnutls_import.}
proc gnutls_x509_dn_init*(dn: ptr gnutls_x509_dn_t): cint {.
    importc: "gnutls_x509_dn_init", gnutls_import.}
proc gnutls_x509_dn_import*(dn: gnutls_x509_dn_t; data: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_dn_import", gnutls_import.}
proc gnutls_x509_dn_export*(dn: gnutls_x509_dn_t; format: gnutls_x509_crt_fmt_t;
                           output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_dn_export", gnutls_import.}
proc gnutls_x509_dn_export2*(dn: gnutls_x509_dn_t; format: gnutls_x509_crt_fmt_t;
                            `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_dn_export2", gnutls_import.}
proc gnutls_x509_dn_deinit*(dn: gnutls_x509_dn_t) {.
    importc: "gnutls_x509_dn_deinit", gnutls_import.}
##  CRL handling functions.
##

proc gnutls_x509_crl_init*(crl: ptr gnutls_x509_crl_t): cint {.
    importc: "gnutls_x509_crl_init", gnutls_import.}
proc gnutls_x509_crl_deinit*(crl: gnutls_x509_crl_t) {.
    importc: "gnutls_x509_crl_deinit", gnutls_import.}
proc gnutls_x509_crl_import*(crl: gnutls_x509_crl_t; data: ptr gnutls_datum_t;
                            format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_crl_import", gnutls_import.}
proc gnutls_x509_crl_export*(crl: gnutls_x509_crl_t; format: gnutls_x509_crt_fmt_t;
                            output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_crl_export", gnutls_import.}
proc gnutls_x509_crl_export2*(crl: gnutls_x509_crl_t;
                             format: gnutls_x509_crt_fmt_t;
                             `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crl_export2", gnutls_import.}
proc gnutls_x509_crl_get_raw_issuer_dn*(crl: gnutls_x509_crl_t;
                                       dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crl_get_raw_issuer_dn", gnutls_import.}
proc gnutls_x509_crl_get_issuer_dn*(crl: gnutls_x509_crl_t; buf: cstring;
                                   sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_issuer_dn", gnutls_import.}
proc gnutls_x509_crl_get_issuer_dn2*(crl: gnutls_x509_crl_t; dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crl_get_issuer_dn2", gnutls_import.}
proc gnutls_x509_crl_get_issuer_dn3*(crl: gnutls_x509_crl_t;
                                    dn: ptr gnutls_datum_t; flags: cuint): cint {.
    importc: "gnutls_x509_crl_get_issuer_dn3", gnutls_import.}
proc gnutls_x509_crl_get_issuer_dn_by_oid*(crl: gnutls_x509_crl_t; oid: cstring;
    indx: cuint; raw_flag: cuint; buf: pointer; sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_issuer_dn_by_oid", gnutls_import.}
proc gnutls_x509_crl_get_dn_oid*(crl: gnutls_x509_crl_t; indx: cuint; oid: pointer;
                                sizeof_oid: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_dn_oid", gnutls_import.}
proc gnutls_x509_crl_get_signature_algorithm*(crl: gnutls_x509_crl_t): cint {.
    importc: "gnutls_x509_crl_get_signature_algorithm", gnutls_import.}
proc gnutls_x509_crl_get_signature*(crl: gnutls_x509_crl_t; sig: cstring;
                                   sizeof_sig: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_signature", gnutls_import.}
proc gnutls_x509_crl_get_version*(crl: gnutls_x509_crl_t): cint {.
    importc: "gnutls_x509_crl_get_version", gnutls_import.}
proc gnutls_x509_crl_get_signature_oid*(crl: gnutls_x509_crl_t; oid: cstring;
                                       oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_signature_oid", gnutls_import.}
proc gnutls_x509_crl_get_this_update*(crl: gnutls_x509_crl_t): time_t {.
    importc: "gnutls_x509_crl_get_this_update", gnutls_import.}
proc gnutls_x509_crl_get_next_update*(crl: gnutls_x509_crl_t): time_t {.
    importc: "gnutls_x509_crl_get_next_update", gnutls_import.}
proc gnutls_x509_crl_get_crt_count*(crl: gnutls_x509_crl_t): cint {.
    importc: "gnutls_x509_crl_get_crt_count", gnutls_import.}
proc gnutls_x509_crl_get_crt_serial*(crl: gnutls_x509_crl_t; indx: cuint;
                                    serial: ptr cuchar; serial_size: ptr csize;
                                    t: ptr time_t): cint {.
    importc: "gnutls_x509_crl_get_crt_serial", gnutls_import.}
type
  gnutls_x509_crl_iter = object
  gnutls_x509_crl_iter_t* = ptr gnutls_x509_crl_iter

proc gnutls_x509_crl_iter_crt_serial*(crl: gnutls_x509_crl_t;
                                     a2: ptr gnutls_x509_crl_iter_t;
                                     serial: ptr cuchar; serial_size: ptr csize;
                                     t: ptr time_t): cint {.
    importc: "gnutls_x509_crl_iter_crt_serial", gnutls_import.}
proc gnutls_x509_crl_iter_deinit*(a1: gnutls_x509_crl_iter_t) {.
    importc: "gnutls_x509_crl_iter_deinit", gnutls_import.}
const
  gnutls_x509_crl_get_certificate_count* = gnutls_x509_crl_get_crt_count
  gnutls_x509_crl_get_certificate* = gnutls_x509_crl_get_crt_serial

proc gnutls_x509_crl_check_issuer*(crl: gnutls_x509_crl_t;
                                  issuer: gnutls_x509_crt_t): cuint {.
    importc: "gnutls_x509_crl_check_issuer", gnutls_import.}
proc gnutls_x509_crl_list_import2*(crls: ptr ptr gnutls_x509_crl_t; size: ptr cuint;
                                  data: ptr gnutls_datum_t;
                                  format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_x509_crl_list_import2", gnutls_import.}
proc gnutls_x509_crl_list_import*(crls: ptr gnutls_x509_crl_t; crl_max: ptr cuint;
                                 data: ptr gnutls_datum_t;
                                 format: gnutls_x509_crt_fmt_t; flags: cuint): cint {.
    importc: "gnutls_x509_crl_list_import", gnutls_import.}
##  CRL writing.
##

proc gnutls_x509_crl_set_version*(crl: gnutls_x509_crl_t; version: cuint): cint {.
    importc: "gnutls_x509_crl_set_version", gnutls_import.}
proc gnutls_x509_crl_set_this_update*(crl: gnutls_x509_crl_t; act_time: time_t): cint {.
    importc: "gnutls_x509_crl_set_this_update", gnutls_import.}
proc gnutls_x509_crl_set_next_update*(crl: gnutls_x509_crl_t; exp_time: time_t): cint {.
    importc: "gnutls_x509_crl_set_next_update", gnutls_import.}
proc gnutls_x509_crl_set_crt_serial*(crl: gnutls_x509_crl_t; serial: pointer;
                                    serial_size: csize; revocation_time: time_t): cint {.
    importc: "gnutls_x509_crl_set_crt_serial", gnutls_import.}
proc gnutls_x509_crl_set_crt*(crl: gnutls_x509_crl_t; crt: gnutls_x509_crt_t;
                             revocation_time: time_t): cint {.
    importc: "gnutls_x509_crl_set_crt", gnutls_import.}
proc gnutls_x509_crl_get_authority_key_id*(crl: gnutls_x509_crl_t; id: pointer;
    id_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crl_get_authority_key_id", gnutls_import.}
proc gnutls_x509_crl_get_authority_key_gn_serial*(crl: gnutls_x509_crl_t;
    seq: cuint; alt: pointer; alt_size: ptr csize; alt_type: ptr cuint; serial: pointer;
    serial_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crl_get_authority_key_gn_serial", gnutls_import.}
proc gnutls_x509_crl_get_number*(crl: gnutls_x509_crl_t; ret: pointer;
                                ret_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crl_get_number", gnutls_import.}
proc gnutls_x509_crl_get_extension_oid*(crl: gnutls_x509_crl_t; indx: cuint;
                                       oid: pointer; sizeof_oid: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_extension_oid", gnutls_import.}
proc gnutls_x509_crl_get_extension_info*(crl: gnutls_x509_crl_t; indx: cuint;
                                        oid: pointer; sizeof_oid: ptr csize;
                                        critical: ptr cuint): cint {.
    importc: "gnutls_x509_crl_get_extension_info", gnutls_import.}
proc gnutls_x509_crl_get_extension_data*(crl: gnutls_x509_crl_t; indx: cuint;
                                        data: pointer; sizeof_data: ptr csize): cint {.
    importc: "gnutls_x509_crl_get_extension_data", gnutls_import.}
proc gnutls_x509_crl_get_extension_data2*(crl: gnutls_x509_crl_t; indx: cuint;
    data: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_crl_get_extension_data2",
                                  gnutls_import.}
proc gnutls_x509_crl_set_authority_key_id*(crl: gnutls_x509_crl_t; id: pointer;
    id_size: csize): cint {.importc: "gnutls_x509_crl_set_authority_key_id",
                         gnutls_import.}
proc gnutls_x509_crl_set_number*(crl: gnutls_x509_crl_t; nr: pointer; nr_size: csize): cint {.
    importc: "gnutls_x509_crl_set_number", gnutls_import.}
##  X.509 Certificate verification functions.
##
## *
##  gnutls_certificate_verify_flags:
##  @GNUTLS_VERIFY_DISABLE_CA_SIGN: If set a signer does not have to be
##    a certificate authority. This flag should normally be disabled,
##    unless you know what this means.
##  @GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS: If set a signer in the trusted
##    list is never checked for expiration or activation.
##  @GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT: Do not allow trusted CA
##    certificates that have version 1.  This option is to be used
##    to deprecate all certificates of version 1.
##  @GNUTLS_VERIFY_DO_NOT_ALLOW_SAME: If a certificate is not signed by
##    anyone trusted but exists in the trusted CA list do not treat it
##    as trusted.
##  @GNUTLS_VERIFY_ALLOW_UNSORTED_CHAIN: A certificate chain is tolerated
##    if unsorted (the case with many TLS servers out there). This is the
##    default since GnuTLS 3.1.4.
##  @GNUTLS_VERIFY_DO_NOT_ALLOW_UNSORTED_CHAIN: Do not tolerate an unsorted
##    certificate chain.
##  @GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT: Allow CA certificates that
##    have version 1 (both root and intermediate). This might be
##    dangerous since those haven't the basicConstraints
##    extension.
##  @GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2: Allow certificates to be signed
##    using the broken MD2 algorithm.
##  @GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5: Allow certificates to be signed
##    using the broken MD5 algorithm.
##  @GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1: Allow certificates to be signed
##    using the broken SHA1 hash algorithm.
##  @GNUTLS_VERIFY_ALLOW_BROKEN: Allow certificates to be signed
##    using any broken algorithm.
##  @GNUTLS_VERIFY_DISABLE_TIME_CHECKS: Disable checking of activation
##    and expiration validity periods of certificate chains. Don't set
##    this unless you understand the security implications.
##  @GNUTLS_VERIFY_DISABLE_CRL_CHECKS: Disable checking for validity
##    using certificate revocation lists or the available OCSP data.
##  @GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS: When including a hostname
##    check in the verification, do not consider any wildcards.
##  @GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES: When verifying a hostname
##    prevent textual IP addresses from matching IP addresses in the
##    certificate. Treat the input only as a DNS name.
##  @GNUTLS_VERIFY_USE_TLS1_RSA: This indicates that a (raw) RSA signature is provided
##    as in the TLS 1.0 protocol. Not all functions accept this flag.
##  @GNUTLS_VERIFY_IGNORE_UNKNOWN_CRIT_EXTENSIONS: This signals the verification
##    process, not to fail on unknown critical extensions.
##
##  Enumeration of different certificate verify flags. Additional
##  verification profiles can be set using GNUTLS_PROFILE_TO_VFLAGS()
##  and %gnutls_certificate_verification_profiles_t.
##

type
  gnutls_certificate_verify_flags* {.size: sizeof(cint).} = enum
    GNUTLS_VERIFY_DISABLE_CA_SIGN = 1 shl 0,
    GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES = 1 shl 1,
    GNUTLS_VERIFY_DO_NOT_ALLOW_SAME = 1 shl 2,
    GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT = 1 shl 3,
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 = 1 shl 4,
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5 = 1 shl 5,
    GNUTLS_VERIFY_DISABLE_TIME_CHECKS = 1 shl 6,
    GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS = 1 shl 7,
    GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT = 1 shl 8,
    GNUTLS_VERIFY_DISABLE_CRL_CHECKS = 1 shl 9,
    GNUTLS_VERIFY_ALLOW_UNSORTED_CHAIN = 1 shl 10,
    GNUTLS_VERIFY_DO_NOT_ALLOW_UNSORTED_CHAIN = 1 shl 11,
    GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS = 1 shl 12,
    GNUTLS_VERIFY_USE_TLS1_RSA = 1 shl 13,
    GNUTLS_VERIFY_IGNORE_UNKNOWN_CRIT_EXTENSIONS = 1 shl 14,
    GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1 = 1 shl 15


##  cannot exceed 2^24 due to GNUTLS_PROFILE_TO_VFLAGS()

#const GNUTLS_VERIFY_ALLOW_BROKEN* = ( GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 or GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)

## *
##  gnutls_certificate_verification_profiles_t:
##  @GNUTLS_PROFILE_VERY_WEAK: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_VERY_WEAK (64 bits)
##  @GNUTLS_PROFILE_LOW: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_LOW (80 bits)
##  @GNUTLS_PROFILE_LEGACY: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_LEGACY (96 bits)
##  @GNUTLS_PROFILE_MEDIUM: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_MEDIUM (112 bits)
##  @GNUTLS_PROFILE_HIGH: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_HIGH (128 bits)
##  @GNUTLS_PROFILE_ULTRA: A verification profile that
##   corresponds to @GNUTLS_SEC_PARAM_ULTRA (256 bits)
## % * @GNUTLS_PROFILE_SUITEB128: A verification profile that
##   applies the SUITEB128 rules
##  @GNUTLS_PROFILE_SUITEB192: A verification profile that
##   applies the SUITEB192 rules
##
##  Enumeration of different certificate verification profiles.
##

type
  gnutls_certificate_verification_profiles_t* {.size: sizeof(cint).} = enum
    GNUTLS_PROFILE_VERY_WEAK = 1, GNUTLS_PROFILE_LOW = 2, GNUTLS_PROFILE_LEGACY = 4,
    GNUTLS_PROFILE_MEDIUM = 5, GNUTLS_PROFILE_HIGH = 6, GNUTLS_PROFILE_ULTRA = 7,
    GNUTLS_PROFILE_SUITEB128 = 32, GNUTLS_PROFILE_SUITEB192 = 33


## GNUTLS_PROFILE_MAX=255

template GNUTLS_PROFILE_TO_VFLAGS*(x: untyped): untyped =
  ((cast[cuint](x)) shl 24)

const
  GNUTLS_VFLAGS_PROFILE_MASK* = (0xFF000000)

template GNUTLS_VFLAGS_TO_PROFILE*(x: untyped): untyped =
  (((cast[cuint](x)) shr 24) and 0x000000FF)

proc gnutls_x509_crt_check_issuer*(cert: gnutls_x509_crt_t;
                                  issuer: gnutls_x509_crt_t): cuint {.
    importc: "gnutls_x509_crt_check_issuer", gnutls_import.}
proc gnutls_x509_crt_list_verify*(cert_list: ptr gnutls_x509_crt_t;
                                 cert_list_length: cuint;
                                 CA_list: ptr gnutls_x509_crt_t;
                                 CA_list_length: cuint;
                                 CRL_list: ptr gnutls_x509_crl_t;
                                 CRL_list_length: cuint; flags: cuint;
                                 verify: ptr cuint): cint {.
    importc: "gnutls_x509_crt_list_verify", gnutls_import.}
proc gnutls_x509_crt_verify*(cert: gnutls_x509_crt_t;
                            CA_list: ptr gnutls_x509_crt_t; CA_list_length: cuint;
                            flags: cuint; verify: ptr cuint): cint {.
    importc: "gnutls_x509_crt_verify", gnutls_import.}
proc gnutls_x509_crl_verify*(crl: gnutls_x509_crl_t;
                            CA_list: ptr gnutls_x509_crt_t; CA_list_length: cuint;
                            flags: cuint; verify: ptr cuint): cint {.
    importc: "gnutls_x509_crl_verify", gnutls_import.}
proc gnutls_x509_crt_verify_data2*(crt: gnutls_x509_crt_t;
                                  algo: gnutls_sign_algorithm_t; flags: cuint;
                                  data: ptr gnutls_datum_t;
                                  signature: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crt_verify_data2", gnutls_import.}
proc gnutls_x509_crt_check_revocation*(cert: gnutls_x509_crt_t;
                                      crl_list: ptr gnutls_x509_crl_t;
                                      crl_list_length: cuint): cint {.
    importc: "gnutls_x509_crt_check_revocation", gnutls_import.}
proc gnutls_x509_crt_get_fingerprint*(cert: gnutls_x509_crt_t;
                                     algo: gnutls_digest_algorithm_t;
                                     buf: pointer; buf_size: ptr csize): cint {.
    importc: "gnutls_x509_crt_get_fingerprint", gnutls_import.}
proc gnutls_x509_crt_get_key_purpose_oid*(cert: gnutls_x509_crt_t; indx: cuint;
    oid: pointer; oid_size: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_key_purpose_oid", gnutls_import.}
proc gnutls_x509_crt_set_key_purpose_oid*(cert: gnutls_x509_crt_t; oid: pointer;
    critical: cuint): cint {.importc: "gnutls_x509_crt_set_key_purpose_oid",
                          gnutls_import.}
proc gnutls_x509_crt_check_key_purpose*(cert: gnutls_x509_crt_t; purpose: cstring;
                                       flags: cuint): cuint {.
    importc: "gnutls_x509_crt_check_key_purpose", gnutls_import.}
##  Private key handling.
##
##  Flags for the gnutls_x509_privkey_export_pkcs8() function.
##

## *
##  gnutls_pkcs_encrypt_flags_t:
##  @GNUTLS_PKCS_PLAIN: Unencrypted private key.
##  @GNUTLS_PKCS_NULL_PASSWORD: Some schemas distinguish between an empty and a NULL password.
##  @GNUTLS_PKCS_PKCS12_3DES: PKCS-12 3DES.
##  @GNUTLS_PKCS_PKCS12_ARCFOUR: PKCS-12 ARCFOUR.
##  @GNUTLS_PKCS_PKCS12_RC2_40: PKCS-12 RC2-40.
##  @GNUTLS_PKCS_PBES2_3DES: PBES2 3DES.
##  @GNUTLS_PKCS_PBES2_AES_128: PBES2 AES-128.
##  @GNUTLS_PKCS_PBES2_AES_192: PBES2 AES-192.
##  @GNUTLS_PKCS_PBES2_AES_256: PBES2 AES-256.
##  @GNUTLS_PKCS_PBES2_DES: PBES2 single DES.
##  @GNUTLS_PKCS_PBES1_DES_MD5: PBES1 with single DES; for compatibility with openssl only.
##  @GNUTLS_PKCS_PBES2_GOST_TC26Z: PBES2 GOST 28147-89 CFB with TC26-Z S-box.
##  @GNUTLS_PKCS_PBES2_GOST_CPA: PBES2 GOST 28147-89 CFB with CryptoPro-A S-box.
##  @GNUTLS_PKCS_PBES2_GOST_CPB: PBES2 GOST 28147-89 CFB with CryptoPro-B S-box.
##  @GNUTLS_PKCS_PBES2_GOST_CPC: PBES2 GOST 28147-89 CFB with CryptoPro-C S-box.
##  @GNUTLS_PKCS_PBES2_GOST_CPD: PBES2 GOST 28147-89 CFB with CryptoPro-D S-box.
##
##  Enumeration of different PKCS encryption flags.
##

type
  gnutls_pkcs_encrypt_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_PKCS_PLAIN = 1, GNUTLS_PKCS_PKCS12_3DES = 1 shl 1,
    GNUTLS_PKCS_PKCS12_ARCFOUR = 1 shl 2, GNUTLS_PKCS_PKCS12_RC2_40 = 1 shl 3,
    GNUTLS_PKCS_PBES2_3DES = 1 shl 4, GNUTLS_PKCS_PBES2_AES_128 = 1 shl 5,
    GNUTLS_PKCS_PBES2_AES_192 = 1 shl 6, GNUTLS_PKCS_PBES2_AES_256 = 1 shl 7,
    GNUTLS_PKCS_NULL_PASSWORD = 1 shl 8, GNUTLS_PKCS_PBES2_DES = 1 shl 9,
    GNUTLS_PKCS_PBES1_DES_MD5 = 1 shl 10, GNUTLS_PKCS_PBES2_GOST_TC26Z = 1 shl 11,
    GNUTLS_PKCS_PBES2_GOST_CPA = 1 shl 12, GNUTLS_PKCS_PBES2_GOST_CPB = 1 shl 13,
    GNUTLS_PKCS_PBES2_GOST_CPC = 1 shl 14, GNUTLS_PKCS_PBES2_GOST_CPD = 1 shl 15

const
  GNUTLS_PKCS8_PLAIN* = GNUTLS_PKCS_PLAIN
  GNUTLS_PKCS8_USE_PKCS12_3DES* = GNUTLS_PKCS_PKCS12_3DES
  GNUTLS_PKCS8_USE_PKCS12_ARCFOUR* = GNUTLS_PKCS_PKCS12_ARCFOUR
  GNUTLS_PKCS8_USE_PKCS12_RC2_40* = GNUTLS_PKCS_PKCS12_RC2_40


template GNUTLS_PKCS_CIPHER_MASK*(x: untyped): untyped =
  ((x) and (not (GNUTLS_PKCS_NULL_PASSWORD)))

const
  GNUTLS_PKCS_USE_PKCS12_3DES* = GNUTLS_PKCS_PKCS12_3DES
  GNUTLS_PKCS_USE_PKCS12_ARCFOUR* = GNUTLS_PKCS_PKCS12_ARCFOUR
  GNUTLS_PKCS_USE_PKCS12_RC2_40* = GNUTLS_PKCS_PKCS12_RC2_40
  GNUTLS_PKCS_USE_PBES2_3DES* = GNUTLS_PKCS_PBES2_3DES
  GNUTLS_PKCS_USE_PBES2_AES_128* = GNUTLS_PKCS_PBES2_AES_128
  GNUTLS_PKCS_USE_PBES2_AES_192* = GNUTLS_PKCS_PBES2_AES_192
  GNUTLS_PKCS_USE_PBES2_AES_256* = GNUTLS_PKCS_PBES2_AES_256
  GNUTLS_PKCS_USE_PBES2_GOST_TC26Z* = GNUTLS_PKCS_PBES2_GOST_TC26Z
  GNUTLS_PKCS_USE_PBES2_GOST_CPA* = GNUTLS_PKCS_PBES2_GOST_CPA
  GNUTLS_PKCS_USE_PBES2_GOST_CPB* = GNUTLS_PKCS_PBES2_GOST_CPB
  GNUTLS_PKCS_USE_PBES2_GOST_CPC* = GNUTLS_PKCS_PBES2_GOST_CPC
  GNUTLS_PKCS_USE_PBES2_GOST_CPD* = GNUTLS_PKCS_PBES2_GOST_CPD

proc gnutls_pkcs_schema_get_name*(schema: cuint): cstring {.
    importc: "gnutls_pkcs_schema_get_name", gnutls_import.}
proc gnutls_pkcs_schema_get_oid*(schema: cuint): cstring {.
    importc: "gnutls_pkcs_schema_get_oid", gnutls_import.}
proc gnutls_x509_privkey_init*(key: ptr gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_privkey_init", gnutls_import.}
proc gnutls_x509_privkey_deinit*(key: gnutls_x509_privkey_t) {.
    importc: "gnutls_x509_privkey_deinit", gnutls_import.}
proc gnutls_x509_privkey_sec_param*(key: gnutls_x509_privkey_t): gnutls_sec_param_t {.
    importc: "gnutls_x509_privkey_sec_param", gnutls_import.}
proc gnutls_x509_privkey_set_pin_function*(key: gnutls_x509_privkey_t;
    fn: gnutls_pin_callback_t; userdata: pointer) {.
    importc: "gnutls_x509_privkey_set_pin_function", gnutls_import.}
proc gnutls_x509_privkey_cpy*(dst: gnutls_x509_privkey_t;
                             src: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_privkey_cpy", gnutls_import.}
proc gnutls_x509_privkey_import*(key: gnutls_x509_privkey_t;
                                data: ptr gnutls_datum_t;
                                format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_privkey_import", gnutls_import.}
proc gnutls_x509_privkey_import_pkcs8*(key: gnutls_x509_privkey_t;
                                      data: ptr gnutls_datum_t;
                                      format: gnutls_x509_crt_fmt_t;
                                      password: cstring; flags: cuint): cint {.
    importc: "gnutls_x509_privkey_import_pkcs8", gnutls_import.}
proc gnutls_x509_privkey_import_openssl*(key: gnutls_x509_privkey_t;
                                        data: ptr gnutls_datum_t; password: cstring): cint {.
    importc: "gnutls_x509_privkey_import_openssl", gnutls_import.}
proc gnutls_pkcs8_info*(data: ptr gnutls_datum_t; format: gnutls_x509_crt_fmt_t;
                       schema: ptr cuint; cipher: ptr cuint; salt: pointer;
                       salt_size: ptr cuint; iter_count: ptr cuint; oid: cstringArray): cint {.
    importc: "gnutls_pkcs8_info", gnutls_import.}
proc gnutls_x509_privkey_import2*(key: gnutls_x509_privkey_t;
                                 data: ptr gnutls_datum_t;
                                 format: gnutls_x509_crt_fmt_t; password: cstring;
                                 flags: cuint): cint {.
    importc: "gnutls_x509_privkey_import2", gnutls_import.}
proc gnutls_x509_privkey_import_rsa_raw*(key: gnutls_x509_privkey_t;
                                        m: ptr gnutls_datum_t;
                                        e: ptr gnutls_datum_t;
                                        d: ptr gnutls_datum_t;
                                        p: ptr gnutls_datum_t;
                                        q: ptr gnutls_datum_t;
                                        u: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_import_rsa_raw", gnutls_import.}
proc gnutls_x509_privkey_import_rsa_raw2*(key: gnutls_x509_privkey_t;
    m: ptr gnutls_datum_t; e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
    p: ptr gnutls_datum_t; q: ptr gnutls_datum_t; u: ptr gnutls_datum_t;
    e1: ptr gnutls_datum_t; e2: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_import_rsa_raw2", gnutls_import.}
proc gnutls_x509_privkey_import_ecc_raw*(key: gnutls_x509_privkey_t;
                                        curve: gnutls_ecc_curve_t;
                                        x: ptr gnutls_datum_t;
                                        y: ptr gnutls_datum_t;
                                        k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_import_ecc_raw", gnutls_import.}
proc gnutls_x509_privkey_import_gost_raw*(key: gnutls_x509_privkey_t;
    curve: gnutls_ecc_curve_t; digest: gnutls_digest_algorithm_t;
    paramset: gnutls_gost_paramset_t; x: ptr gnutls_datum_t; y: ptr gnutls_datum_t;
    k: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_privkey_import_gost_raw",
                               gnutls_import.}
proc gnutls_x509_privkey_fix*(key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_privkey_fix", gnutls_import.}
proc gnutls_x509_privkey_export_dsa_raw*(key: gnutls_x509_privkey_t;
                                        p: ptr gnutls_datum_t;
                                        q: ptr gnutls_datum_t;
                                        g: ptr gnutls_datum_t;
                                        y: ptr gnutls_datum_t;
                                        x: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export_dsa_raw", gnutls_import.}
proc gnutls_x509_privkey_import_dsa_raw*(key: gnutls_x509_privkey_t;
                                        p: ptr gnutls_datum_t;
                                        q: ptr gnutls_datum_t;
                                        g: ptr gnutls_datum_t;
                                        y: ptr gnutls_datum_t;
                                        x: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_import_dsa_raw", gnutls_import.}
proc gnutls_x509_privkey_get_pk_algorithm*(key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_privkey_get_pk_algorithm", gnutls_import.}
proc gnutls_x509_privkey_get_pk_algorithm2*(key: gnutls_x509_privkey_t;
    bits: ptr cuint): cint {.importc: "gnutls_x509_privkey_get_pk_algorithm2",
                         gnutls_import.}
proc gnutls_x509_privkey_get_spki*(key: gnutls_x509_privkey_t;
                                  spki: gnutls_x509_spki_t; flags: cuint): cint {.
    importc: "gnutls_x509_privkey_get_spki", gnutls_import.}
proc gnutls_x509_privkey_set_spki*(key: gnutls_x509_privkey_t;
                                  spki: gnutls_x509_spki_t; flags: cuint): cint {.
    importc: "gnutls_x509_privkey_set_spki", gnutls_import.}
proc gnutls_x509_privkey_get_key_id*(key: gnutls_x509_privkey_t; flags: cuint;
                                    output_data: ptr cuchar;
                                    output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_privkey_get_key_id", gnutls_import.}
proc gnutls_x509_privkey_generate*(key: gnutls_x509_privkey_t;
                                  algo: gnutls_pk_algorithm_t; bits: cuint;
                                  flags: cuint): cint {.
    importc: "gnutls_x509_privkey_generate", gnutls_import.}
proc gnutls_x509_privkey_set_flags*(key: gnutls_x509_privkey_t; flags: cuint) {.
    importc: "gnutls_x509_privkey_set_flags", gnutls_import.}
## *
##  gnutls_keygen_types_t:
##  @GNUTLS_KEYGEN_SEED: Specifies the seed to be used in key generation.
##  @GNUTLS_KEYGEN_DIGEST: The size field specifies the hash algorithm to be used in key generation.
##  @GNUTLS_KEYGEN_SPKI: data points to a %gnutls_x509_spki_t structure; it is not used after the key generation call.
##
##  Enumeration of different key generation data options.
##

type
  gnutls_keygen_types_t* {.size: sizeof(cint).} = enum
    GNUTLS_KEYGEN_SEED = 1, GNUTLS_KEYGEN_DIGEST = 2, GNUTLS_KEYGEN_SPKI = 3
  gnutls_keygen_data_st* {.bycopy.} = object
    `type`*: gnutls_keygen_types_t
    data*: ptr cuchar
    size*: cuint



proc gnutls_x509_privkey_generate2*(key: gnutls_x509_privkey_t;
                                   algo: gnutls_pk_algorithm_t; bits: cuint;
                                   flags: cuint; data: ptr gnutls_keygen_data_st;
                                   data_size: cuint): cint {.
    importc: "gnutls_x509_privkey_generate2", gnutls_import.}
proc gnutls_x509_privkey_verify_seed*(key: gnutls_x509_privkey_t;
                                     a2: gnutls_digest_algorithm_t; seed: pointer;
                                     seed_size: csize): cint {.
    importc: "gnutls_x509_privkey_verify_seed", gnutls_import.}
proc gnutls_x509_privkey_get_seed*(key: gnutls_x509_privkey_t;
                                  a2: ptr gnutls_digest_algorithm_t; seed: pointer;
                                  seed_size: ptr csize): cint {.
    importc: "gnutls_x509_privkey_get_seed", gnutls_import.}
proc gnutls_x509_privkey_verify_params*(key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_privkey_verify_params", gnutls_import.}
proc gnutls_x509_privkey_export*(key: gnutls_x509_privkey_t;
                                format: gnutls_x509_crt_fmt_t;
                                output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_privkey_export", gnutls_import.}
proc gnutls_x509_privkey_export2*(key: gnutls_x509_privkey_t;
                                 format: gnutls_x509_crt_fmt_t;
                                 `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export2", gnutls_import.}
proc gnutls_x509_privkey_export_pkcs8*(key: gnutls_x509_privkey_t;
                                      format: gnutls_x509_crt_fmt_t;
                                      password: cstring; flags: cuint;
                                      output_data: pointer;
                                      output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_privkey_export_pkcs8", gnutls_import.}
proc gnutls_x509_privkey_export2_pkcs8*(key: gnutls_x509_privkey_t;
                                       format: gnutls_x509_crt_fmt_t;
                                       password: cstring; flags: cuint;
                                       `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export2_pkcs8", gnutls_import.}
proc gnutls_x509_privkey_export_rsa_raw2*(key: gnutls_x509_privkey_t;
    m: ptr gnutls_datum_t; e: ptr gnutls_datum_t; d: ptr gnutls_datum_t;
    p: ptr gnutls_datum_t; q: ptr gnutls_datum_t; u: ptr gnutls_datum_t;
    e1: ptr gnutls_datum_t; e2: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export_rsa_raw2", gnutls_import.}
proc gnutls_x509_privkey_export_rsa_raw*(key: gnutls_x509_privkey_t;
                                        m: ptr gnutls_datum_t;
                                        e: ptr gnutls_datum_t;
                                        d: ptr gnutls_datum_t;
                                        p: ptr gnutls_datum_t;
                                        q: ptr gnutls_datum_t;
                                        u: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export_rsa_raw", gnutls_import.}
proc gnutls_x509_privkey_export_ecc_raw*(key: gnutls_x509_privkey_t;
                                        curve: ptr gnutls_ecc_curve_t;
                                        x: ptr gnutls_datum_t;
                                        y: ptr gnutls_datum_t;
                                        k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export_ecc_raw", gnutls_import.}
proc gnutls_x509_privkey_export_gost_raw*(key: gnutls_x509_privkey_t;
    curve: ptr gnutls_ecc_curve_t; digest: ptr gnutls_digest_algorithm_t;
    paramset: ptr gnutls_gost_paramset_t; x: ptr gnutls_datum_t;
    y: ptr gnutls_datum_t; k: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_privkey_export_gost_raw", gnutls_import.}
proc gnutls_x509_privkey_sign_data*(key: gnutls_x509_privkey_t;
                                   digest: gnutls_digest_algorithm_t;
                                   flags: cuint; data: ptr gnutls_datum_t;
                                   signature: pointer; signature_size: ptr csize): cint {.
    importc: "gnutls_x509_privkey_sign_data", gnutls_import.}
##  Certificate request stuff.
##

proc gnutls_x509_crq_sign*(crq: gnutls_x509_crq_t; key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_crq_sign", gnutls_import.}
proc gnutls_x509_crq_sign2*(crq: gnutls_x509_crq_t; key: gnutls_x509_privkey_t;
                           dig: gnutls_digest_algorithm_t; flags: cuint): cint {.
    importc: "gnutls_x509_crq_sign2", gnutls_import.}
proc gnutls_x509_crq_print*(crq: gnutls_x509_crq_t;
                           format: gnutls_certificate_print_formats_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crq_print", gnutls_import.}
proc gnutls_x509_crq_verify*(crq: gnutls_x509_crq_t; flags: cuint): cint {.
    importc: "gnutls_x509_crq_verify", gnutls_import.}
proc gnutls_x509_crq_init*(crq: ptr gnutls_x509_crq_t): cint {.
    importc: "gnutls_x509_crq_init", gnutls_import.}
proc gnutls_x509_crq_deinit*(crq: gnutls_x509_crq_t) {.
    importc: "gnutls_x509_crq_deinit", gnutls_import.}
proc gnutls_x509_crq_import*(crq: gnutls_x509_crq_t; data: ptr gnutls_datum_t;
                            format: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_crq_import", gnutls_import.}
proc gnutls_x509_crq_get_private_key_usage_period*(cert: gnutls_x509_crq_t;
    activation: ptr time_t; expiration: ptr time_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_private_key_usage_period", gnutls_import.}
proc gnutls_x509_crq_get_dn*(crq: gnutls_x509_crq_t; buf: cstring;
                            sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_dn", gnutls_import.}
proc gnutls_x509_crq_get_dn2*(crq: gnutls_x509_crq_t; dn: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crq_get_dn2", gnutls_import.}
proc gnutls_x509_crq_get_dn3*(crq: gnutls_x509_crq_t; dn: ptr gnutls_datum_t;
                             flags: cuint): cint {.
    importc: "gnutls_x509_crq_get_dn3", gnutls_import.}
proc gnutls_x509_crq_get_dn_oid*(crq: gnutls_x509_crq_t; indx: cuint; oid: pointer;
                                sizeof_oid: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_dn_oid", gnutls_import.}
proc gnutls_x509_crq_get_dn_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
                                   indx: cuint; raw_flag: cuint; buf: pointer;
                                   sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_dn_by_oid", gnutls_import.}
proc gnutls_x509_crq_set_dn*(crq: gnutls_x509_crq_t; dn: cstring; err: cstringArray): cint {.
    importc: "gnutls_x509_crq_set_dn", gnutls_import.}
proc gnutls_x509_crq_set_dn_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
                                   raw_flag: cuint; data: pointer;
                                   sizeof_data: cuint): cint {.
    importc: "gnutls_x509_crq_set_dn_by_oid", gnutls_import.}
proc gnutls_x509_crq_set_version*(crq: gnutls_x509_crq_t; version: cuint): cint {.
    importc: "gnutls_x509_crq_set_version", gnutls_import.}
proc gnutls_x509_crq_get_version*(crq: gnutls_x509_crq_t): cint {.
    importc: "gnutls_x509_crq_get_version", gnutls_import.}
proc gnutls_x509_crq_set_key*(crq: gnutls_x509_crq_t; key: gnutls_x509_privkey_t): cint {.
    importc: "gnutls_x509_crq_set_key", gnutls_import.}
proc gnutls_x509_crq_set_extension_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
    buf: pointer; sizeof_buf: csize; critical: cuint): cint {.
    importc: "gnutls_x509_crq_set_extension_by_oid", gnutls_import.}
proc gnutls_x509_crq_set_challenge_password*(crq: gnutls_x509_crq_t; pass: cstring): cint {.
    importc: "gnutls_x509_crq_set_challenge_password", gnutls_import.}
proc gnutls_x509_crq_get_challenge_password*(crq: gnutls_x509_crq_t; pass: cstring;
    sizeof_pass: ptr csize): cint {.importc: "gnutls_x509_crq_get_challenge_password",
                                gnutls_import.}
proc gnutls_x509_crq_set_attribute_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
    buf: pointer; sizeof_buf: csize): cint {.importc: "gnutls_x509_crq_set_attribute_by_oid",
                                        gnutls_import.}
proc gnutls_x509_crq_get_attribute_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
    indx: cuint; buf: pointer; sizeof_buf: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_attribute_by_oid", gnutls_import.}
proc gnutls_x509_crq_export*(crq: gnutls_x509_crq_t; format: gnutls_x509_crt_fmt_t;
                            output_data: pointer; output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_crq_export", gnutls_import.}
proc gnutls_x509_crq_export2*(crq: gnutls_x509_crq_t;
                             format: gnutls_x509_crt_fmt_t;
                             `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crq_export2", gnutls_import.}
proc gnutls_x509_crt_set_crq*(crt: gnutls_x509_crt_t; crq: gnutls_x509_crq_t): cint {.
    importc: "gnutls_x509_crt_set_crq", gnutls_import.}
proc gnutls_x509_crt_set_crq_extensions*(crt: gnutls_x509_crt_t;
                                        crq: gnutls_x509_crq_t): cint {.
    importc: "gnutls_x509_crt_set_crq_extensions", gnutls_import.}
proc gnutls_x509_crt_set_crq_extension_by_oid*(crt: gnutls_x509_crt_t;
    crq: gnutls_x509_crq_t; oid: cstring; flags: cuint): cint {.
    importc: "gnutls_x509_crt_set_crq_extension_by_oid", gnutls_import.}
proc gnutls_x509_crq_set_private_key_usage_period*(crq: gnutls_x509_crq_t;
    activation: time_t; expiration: time_t): cint {.
    importc: "gnutls_x509_crq_set_private_key_usage_period", gnutls_import.}
proc gnutls_x509_crq_set_key_rsa_raw*(crq: gnutls_x509_crq_t;
                                     m: ptr gnutls_datum_t; e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crq_set_key_rsa_raw", gnutls_import.}
proc gnutls_x509_crq_set_subject_alt_name*(crq: gnutls_x509_crq_t;
    nt: gnutls_x509_subject_alt_name_t; data: pointer; data_size: cuint; flags: cuint): cint {.
    importc: "gnutls_x509_crq_set_subject_alt_name", gnutls_import.}
proc gnutls_x509_crq_set_subject_alt_othername*(crq: gnutls_x509_crq_t;
    oid: cstring; data: pointer; data_size: cuint; flags: cuint): cint {.
    importc: "gnutls_x509_crq_set_subject_alt_othername", gnutls_import.}
proc gnutls_x509_crq_set_key_usage*(crq: gnutls_x509_crq_t; usage: cuint): cint {.
    importc: "gnutls_x509_crq_set_key_usage", gnutls_import.}
proc gnutls_x509_crq_set_basic_constraints*(crq: gnutls_x509_crq_t; ca: cuint;
    pathLenConstraint: cint): cint {.importc: "gnutls_x509_crq_set_basic_constraints",
                                  gnutls_import.}
proc gnutls_x509_crq_set_key_purpose_oid*(crq: gnutls_x509_crq_t; oid: pointer;
    critical: cuint): cint {.importc: "gnutls_x509_crq_set_key_purpose_oid",
                          gnutls_import.}
proc gnutls_x509_crq_get_key_purpose_oid*(crq: gnutls_x509_crq_t; indx: cuint;
    oid: pointer; sizeof_oid: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_key_purpose_oid", gnutls_import.}
proc gnutls_x509_crq_get_extension_data*(crq: gnutls_x509_crq_t; indx: cuint;
                                        data: pointer; sizeof_data: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_extension_data", gnutls_import.}
proc gnutls_x509_crq_get_extension_data2*(crq: gnutls_x509_crq_t; indx: cuint;
    data: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_crq_get_extension_data2",
                                  gnutls_import.}
proc gnutls_x509_crq_get_extension_info*(crq: gnutls_x509_crq_t; indx: cuint;
                                        oid: pointer; sizeof_oid: ptr csize;
                                        critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_extension_info", gnutls_import.}
proc gnutls_x509_crq_get_attribute_data*(crq: gnutls_x509_crq_t; indx: cuint;
                                        data: pointer; sizeof_data: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_attribute_data", gnutls_import.}
proc gnutls_x509_crq_get_attribute_info*(crq: gnutls_x509_crq_t; indx: cuint;
                                        oid: pointer; sizeof_oid: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_attribute_info", gnutls_import.}
proc gnutls_x509_crq_get_pk_algorithm*(crq: gnutls_x509_crq_t; bits: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_pk_algorithm", gnutls_import.}
proc gnutls_x509_crq_get_spki*(crq: gnutls_x509_crq_t; spki: gnutls_x509_spki_t;
                              flags: cuint): cint {.
    importc: "gnutls_x509_crq_get_spki", gnutls_import.}
proc gnutls_x509_crq_set_spki*(crq: gnutls_x509_crq_t; spki: gnutls_x509_spki_t;
                              flags: cuint): cint {.
    importc: "gnutls_x509_crq_set_spki", gnutls_import.}
proc gnutls_x509_crq_get_signature_oid*(crq: gnutls_x509_crq_t; oid: cstring;
                                       oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_signature_oid", gnutls_import.}
proc gnutls_x509_crq_get_pk_oid*(crq: gnutls_x509_crq_t; oid: cstring;
                                oid_size: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_pk_oid", gnutls_import.}
proc gnutls_x509_crq_get_key_id*(crq: gnutls_x509_crq_t; flags: cuint;
                                output_data: ptr cuchar;
                                output_data_size: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_key_id", gnutls_import.}
proc gnutls_x509_crq_get_key_rsa_raw*(crq: gnutls_x509_crq_t;
                                     m: ptr gnutls_datum_t; e: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_crq_get_key_rsa_raw", gnutls_import.}
proc gnutls_x509_crq_get_key_usage*(crq: gnutls_x509_crq_t; key_usage: ptr cuint;
                                   critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_key_usage", gnutls_import.}
proc gnutls_x509_crq_get_basic_constraints*(crq: gnutls_x509_crq_t;
    critical: ptr cuint; ca: ptr cuint; pathlen: ptr cint): cint {.
    importc: "gnutls_x509_crq_get_basic_constraints", gnutls_import.}
proc gnutls_x509_crq_get_subject_alt_name*(crq: gnutls_x509_crq_t; seq: cuint;
    ret: pointer; ret_size: ptr csize; ret_type: ptr cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_subject_alt_name", gnutls_import.}
proc gnutls_x509_crq_get_subject_alt_othername_oid*(crq: gnutls_x509_crq_t;
    seq: cuint; ret: pointer; ret_size: ptr csize): cint {.
    importc: "gnutls_x509_crq_get_subject_alt_othername_oid", gnutls_import.}
proc gnutls_x509_crq_get_extension_by_oid*(crq: gnutls_x509_crq_t; oid: cstring;
    indx: cuint; buf: pointer; sizeof_buf: ptr csize; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_extension_by_oid", gnutls_import.}
proc gnutls_x509_crq_get_tlsfeatures*(crq: gnutls_x509_crq_t;
                                     features: gnutls_x509_tlsfeatures_t;
                                     flags: cuint; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crq_get_tlsfeatures", gnutls_import.}
proc gnutls_x509_crq_set_tlsfeatures*(crq: gnutls_x509_crq_t;
                                     features: gnutls_x509_tlsfeatures_t): cint {.
    importc: "gnutls_x509_crq_set_tlsfeatures", gnutls_import.}
proc gnutls_x509_crt_get_extension_by_oid2*(cert: gnutls_x509_crt_t; oid: cstring;
    indx: cuint; output: ptr gnutls_datum_t; critical: ptr cuint): cint {.
    importc: "gnutls_x509_crt_get_extension_by_oid2", gnutls_import.}
type
  gnutls_x509_trust_list_st = object
  gnutls_x509_trust_list_iter = object
  gnutls_x509_trust_list_t* = ptr gnutls_x509_trust_list_st
  gnutls_x509_trust_list_iter_t* = ptr gnutls_x509_trust_list_iter

proc gnutls_x509_trust_list_init*(list: ptr gnutls_x509_trust_list_t; size: cuint): cint {.
    importc: "gnutls_x509_trust_list_init", gnutls_import.}
proc gnutls_x509_trust_list_deinit*(list: gnutls_x509_trust_list_t; all: cuint) {.
    importc: "gnutls_x509_trust_list_deinit", gnutls_import.}
proc gnutls_x509_trust_list_get_issuer*(list: gnutls_x509_trust_list_t;
                                       cert: gnutls_x509_crt_t;
                                       issuer: ptr gnutls_x509_crt_t; flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_get_issuer", gnutls_import.}
proc gnutls_x509_trust_list_get_issuer_by_dn*(list: gnutls_x509_trust_list_t;
    dn: ptr gnutls_datum_t; issuer: ptr gnutls_x509_crt_t; flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_get_issuer_by_dn", gnutls_import.}
proc gnutls_x509_trust_list_get_issuer_by_subject_key_id*(
    list: gnutls_x509_trust_list_t; dn: ptr gnutls_datum_t; spki: ptr gnutls_datum_t;
    issuer: ptr gnutls_x509_crt_t; flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_get_issuer_by_subject_key_id", gnutls_import.}
## *
##  gnutls_trust_list_flags_t:
##  @GNUTLS_TL_VERIFY_CRL: If any CRLs are provided they will be verified for validity
##    prior to be added. The CA certificates that will be used for verification are the
##    ones already added in the trusted list.
##  @GNUTLS_TL_USE_IN_TLS: Internal flag used by GnuTLS. If provided the trust list
##    structure will cache a copy of CA DNs to be used in the certificate request
##    TLS message.
##  @GNUTLS_TL_NO_DUPLICATES: If this flag is specified, a function adding certificates
##    will check and eliminate any duplicates.
##  @GNUTLS_TL_NO_DUPLICATE_KEY: If this flag is specified, a certificate sharing the
##    same key as a previously added on will not be added.
##  @GNUTLS_TL_GET_COPY: The semantics of this flag are documented to the functions which
##    are applicable. In general, on returned value, the function will provide a copy
##    if this flag is provided, rather than a pointer to internal data.
##  @GNUTLS_TL_FAIL_ON_INVALID_CRL: If an CRL is added which cannot be validated return
##    an error instead of ignoring (must be used with %GNUTLS_TL_VERIFY_CRL).
##
##  Enumeration of different certificate trust list flags.
##

type
  gnutls_trust_list_flags_t* {.size: sizeof(cint).} = enum
    GNUTLS_TL_VERIFY_CRL = 1,   ## #define GNUTLS_TL_VERIFY_CRL 1
    GNUTLS_TL_USE_IN_TLS = (1 shl 1), ## #define GNUTLS_TL_USE_IN_TLS (1<<1)
    GNUTLS_TL_NO_DUPLICATES = (1 shl 2), ## #define GNUTLS_TL_NO_DUPLICATES (1<<2)
    GNUTLS_TL_NO_DUPLICATE_KEY = (1 shl 3), ## #define GNUTLS_TL_NO_DUPLICATE_KEY (1<<3)
    GNUTLS_TL_GET_COPY = (1 shl 4), ## #define GNUTLS_TL_GET_COPY (1<<4)
    GNUTLS_TL_FAIL_ON_INVALID_CRL = (1 shl 5) ## #define GNUTLS_TL_FAIL_ON_INVALID_CRL (1<<5)


proc gnutls_x509_trust_list_add_cas*(list: gnutls_x509_trust_list_t;
                                    clist: ptr gnutls_x509_crt_t;
                                    clist_size: cuint; flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_cas", gnutls_import.}
proc gnutls_x509_trust_list_remove_cas*(list: gnutls_x509_trust_list_t;
                                       clist: ptr gnutls_x509_crt_t;
                                       clist_size: cuint): cint {.
    importc: "gnutls_x509_trust_list_remove_cas", gnutls_import.}
proc gnutls_x509_trust_list_add_named_crt*(list: gnutls_x509_trust_list_t;
    cert: gnutls_x509_crt_t; name: pointer; name_size: csize; flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_named_crt", gnutls_import.}
proc gnutls_x509_trust_list_add_crls*(list: gnutls_x509_trust_list_t;
                                     crl_list: ptr gnutls_x509_crl_t;
                                     crl_size: cuint; flags: cuint;
                                     verification_flags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_crls", gnutls_import.}
proc gnutls_x509_trust_list_iter_get_ca*(list: gnutls_x509_trust_list_t; iter: ptr gnutls_x509_trust_list_iter_t;
                                        crt: ptr gnutls_x509_crt_t): cint {.
    importc: "gnutls_x509_trust_list_iter_get_ca", gnutls_import.}
proc gnutls_x509_trust_list_iter_deinit*(iter: gnutls_x509_trust_list_iter_t) {.
    importc: "gnutls_x509_trust_list_iter_deinit", gnutls_import.}
type
  gnutls_verify_output_function* = proc (cert: gnutls_x509_crt_t;
                                      issuer: gnutls_x509_crt_t;
                                      crl: gnutls_x509_crl_t;
                                      verification_output: cuint): cint ##  The issuer if verification failed
                                                                     ##  because of him. might be null.
                                                                     ##
                                                                     ##  The CRL that caused verification failure
                                                                     ##  if any. Might be null.
                                                                     ##

proc gnutls_x509_trust_list_verify_named_crt*(list: gnutls_x509_trust_list_t;
    cert: gnutls_x509_crt_t; name: pointer; name_size: csize; flags: cuint;
    verify: ptr cuint; `func`: gnutls_verify_output_function): cint {.
    importc: "gnutls_x509_trust_list_verify_named_crt", gnutls_import.}
proc gnutls_x509_trust_list_verify_crt2*(list: gnutls_x509_trust_list_t;
                                        cert_list: ptr gnutls_x509_crt_t;
                                        cert_list_size: cuint;
                                        data: ptr gnutls_typed_vdata_st;
                                        elements: cuint; flags: cuint;
                                        voutput: ptr cuint;
                                        `func`: gnutls_verify_output_function): cint {.
    importc: "gnutls_x509_trust_list_verify_crt2", gnutls_import.}
proc gnutls_x509_trust_list_verify_crt*(list: gnutls_x509_trust_list_t;
                                       cert_list: ptr gnutls_x509_crt_t;
                                       cert_list_size: cuint; flags: cuint;
                                       verify: ptr cuint;
                                       `func`: gnutls_verify_output_function): cint {.
    importc: "gnutls_x509_trust_list_verify_crt", gnutls_import.}
##  trust list convenience functions

proc gnutls_x509_trust_list_add_trust_mem*(list: gnutls_x509_trust_list_t;
    cas: ptr gnutls_datum_t; crls: ptr gnutls_datum_t; `type`: gnutls_x509_crt_fmt_t;
    tl_flags: cuint; tl_vflags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_trust_mem", gnutls_import.}
proc gnutls_x509_trust_list_add_trust_file*(list: gnutls_x509_trust_list_t;
    ca_file: cstring; crl_file: cstring; `type`: gnutls_x509_crt_fmt_t;
    tl_flags: cuint; tl_vflags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_trust_file", gnutls_import.}
proc gnutls_x509_trust_list_add_trust_dir*(list: gnutls_x509_trust_list_t;
    ca_dir: cstring; crl_dir: cstring; `type`: gnutls_x509_crt_fmt_t; tl_flags: cuint;
    tl_vflags: cuint): cint {.importc: "gnutls_x509_trust_list_add_trust_dir",
                           gnutls_import.}
proc gnutls_x509_trust_list_remove_trust_file*(list: gnutls_x509_trust_list_t;
    ca_file: cstring; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_trust_list_remove_trust_file", gnutls_import.}
proc gnutls_x509_trust_list_remove_trust_mem*(list: gnutls_x509_trust_list_t;
    cas: ptr gnutls_datum_t; `type`: gnutls_x509_crt_fmt_t): cint {.
    importc: "gnutls_x509_trust_list_remove_trust_mem", gnutls_import.}
proc gnutls_x509_trust_list_add_system_trust*(list: gnutls_x509_trust_list_t;
    tl_flags: cuint; tl_vflags: cuint): cint {.
    importc: "gnutls_x509_trust_list_add_system_trust", gnutls_import.}
proc gnutls_certificate_set_trust_list*(res: gnutls_certificate_credentials_t;
                                       tlist: gnutls_x509_trust_list_t;
                                       flags: cuint) {.
    importc: "gnutls_certificate_set_trust_list", gnutls_import.}
proc gnutls_certificate_get_trust_list*(res: gnutls_certificate_credentials_t;
                                       tlist: ptr gnutls_x509_trust_list_t) {.
    importc: "gnutls_certificate_get_trust_list", gnutls_import.}
type
  gnutls_x509_ext_st* {.bycopy.} = object
    oid*: cstring
    critical*: cuint
    data*: gnutls_datum_t


proc gnutls_x509_ext_deinit*(ext: ptr gnutls_x509_ext_st) {.
    importc: "gnutls_x509_ext_deinit", gnutls_import.}
proc gnutls_x509_ext_print*(exts: ptr gnutls_x509_ext_st; exts_size: cuint;
                           format: gnutls_certificate_print_formats_t;
                           `out`: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_print", gnutls_import.}

when isMainModule:
  var pk: gnutls_x509_privkey_t
  echo gnutls_x509_privkey_init(addr pk)
