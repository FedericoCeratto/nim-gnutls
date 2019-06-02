import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
import x509
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
##  Prototypes for direct handling of extension data

##  *INDENT-OFF*

##  *INDENT-ON*

type
  gnutls_subject_alt_names_st = object
  gnutls_subject_alt_names_t* = ptr gnutls_subject_alt_names_st

proc gnutls_subject_alt_names_init*(a1: ptr gnutls_subject_alt_names_t): cint {.
    importc: "gnutls_subject_alt_names_init", gnutls_import.}
proc gnutls_subject_alt_names_deinit*(sans: gnutls_subject_alt_names_t) {.
    importc: "gnutls_subject_alt_names_deinit", gnutls_import.}
proc gnutls_subject_alt_names_get*(sans: gnutls_subject_alt_names_t; seq: cuint;
                                  san_type: ptr cuint; san: ptr gnutls_datum_t;
                                  othername_oid: ptr gnutls_datum_t): cint {.
    importc: "gnutls_subject_alt_names_get", gnutls_import.}
proc gnutls_subject_alt_names_set*(sans: gnutls_subject_alt_names_t;
                                  san_type: cuint; san: ptr gnutls_datum_t;
                                  othername_oid: cstring): cint {.
    importc: "gnutls_subject_alt_names_set", gnutls_import.}
proc gnutls_x509_ext_import_subject_alt_names*(ext: ptr gnutls_datum_t;
    a2: gnutls_subject_alt_names_t; flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_subject_alt_names", gnutls_import.}
proc gnutls_x509_ext_export_subject_alt_names*(a1: gnutls_subject_alt_names_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_subject_alt_names",
                                 gnutls_import.}
##  They are exactly the same

#const
#  gnutls_x509_ext_import_issuer_alt_name* = gnutls_x509_ext_import_subject_alt_name
#  gnutls_x509_ext_export_issuer_alt_name* = gnutls_x509_ext_export_subject_alt_name

type
  gnutls_x509_crl_dist_points_st = object
  gnutls_x509_crl_dist_points_t* = ptr gnutls_x509_crl_dist_points_st

proc gnutls_x509_crl_dist_points_init*(a1: ptr gnutls_x509_crl_dist_points_t): cint {.
    importc: "gnutls_x509_crl_dist_points_init", gnutls_import.}
proc gnutls_x509_crl_dist_points_deinit*(a1: gnutls_x509_crl_dist_points_t) {.
    importc: "gnutls_x509_crl_dist_points_deinit", gnutls_import.}
proc gnutls_x509_crl_dist_points_get*(a1: gnutls_x509_crl_dist_points_t;
                                     seq: cuint; `type`: ptr cuint;
                                     dist: ptr gnutls_datum_t;
                                     reason_flags: ptr cuint): cint {.
    importc: "gnutls_x509_crl_dist_points_get", gnutls_import.}
proc gnutls_x509_crl_dist_points_set*(a1: gnutls_x509_crl_dist_points_t;
                                     `type`: gnutls_x509_subject_alt_name_t;
                                     dist: ptr gnutls_datum_t; reason_flags: cuint): cint {.
    importc: "gnutls_x509_crl_dist_points_set", gnutls_import.}
proc gnutls_x509_ext_import_crl_dist_points*(ext: ptr gnutls_datum_t;
    dp: gnutls_x509_crl_dist_points_t; flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_crl_dist_points", gnutls_import.}
proc gnutls_x509_ext_export_crl_dist_points*(dp: gnutls_x509_crl_dist_points_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_crl_dist_points",
                                 gnutls_import.}
proc gnutls_x509_ext_import_name_constraints*(ext: ptr gnutls_datum_t;
    nc: gnutls_x509_name_constraints_t; flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_name_constraints", gnutls_import.}
proc gnutls_x509_ext_export_name_constraints*(nc: gnutls_x509_name_constraints_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_name_constraints",
                                 gnutls_import.}
type
  gnutls_x509_aia_st = object
  gnutls_x509_aia_t* = ptr gnutls_x509_aia_st

proc gnutls_x509_aia_init*(a1: ptr gnutls_x509_aia_t): cint {.
    importc: "gnutls_x509_aia_init", gnutls_import.}
proc gnutls_x509_aia_deinit*(a1: gnutls_x509_aia_t) {.
    importc: "gnutls_x509_aia_deinit", gnutls_import.}
proc gnutls_x509_aia_get*(aia: gnutls_x509_aia_t; seq: cuint;
                         oid: ptr gnutls_datum_t; san_type: ptr cuint;
                         san: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aia_get", gnutls_import.}
proc gnutls_x509_aia_set*(aia: gnutls_x509_aia_t; oid: cstring; san_type: cuint;
                         san: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aia_set", gnutls_import.}
proc gnutls_x509_ext_import_aia*(ext: ptr gnutls_datum_t; a2: gnutls_x509_aia_t;
                                flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_aia", gnutls_import.}
proc gnutls_x509_ext_export_aia*(aia: gnutls_x509_aia_t; ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_aia", gnutls_import.}
proc gnutls_x509_ext_import_subject_key_id*(ext: ptr gnutls_datum_t;
    id: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_import_subject_key_id",
                                gnutls_import.}
proc gnutls_x509_ext_export_subject_key_id*(id: ptr gnutls_datum_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_subject_key_id",
                                 gnutls_import.}
type
  gnutls_x509_aki_st = object
  gnutls_x509_aki_t* = ptr gnutls_x509_aki_st

proc gnutls_x509_ext_export_authority_key_id*(a1: gnutls_x509_aki_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_authority_key_id",
                                 gnutls_import.}
proc gnutls_x509_ext_import_authority_key_id*(ext: ptr gnutls_datum_t;
    a2: gnutls_x509_aki_t; flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_authority_key_id", gnutls_import.}
proc gnutls_x509_othername_to_virtual*(oid: cstring; othername: ptr gnutls_datum_t;
                                      virt_type: ptr cuint;
                                      virt: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_othername_to_virtual", gnutls_import.}
proc gnutls_x509_aki_init*(a1: ptr gnutls_x509_aki_t): cint {.
    importc: "gnutls_x509_aki_init", gnutls_import.}
proc gnutls_x509_aki_get_id*(a1: gnutls_x509_aki_t; id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aki_get_id", gnutls_import.}
proc gnutls_x509_aki_get_cert_issuer*(aki: gnutls_x509_aki_t; seq: cuint;
                                     san_type: ptr cuint; san: ptr gnutls_datum_t;
                                     othername_oid: ptr gnutls_datum_t;
                                     serial: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aki_get_cert_issuer", gnutls_import.}
proc gnutls_x509_aki_set_id*(aki: gnutls_x509_aki_t; id: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aki_set_id", gnutls_import.}
proc gnutls_x509_aki_set_cert_issuer*(aki: gnutls_x509_aki_t; san_type: cuint;
                                     san: ptr gnutls_datum_t;
                                     othername_oid: cstring;
                                     serial: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_aki_set_cert_issuer", gnutls_import.}
proc gnutls_x509_aki_deinit*(a1: gnutls_x509_aki_t) {.
    importc: "gnutls_x509_aki_deinit", gnutls_import.}
proc gnutls_x509_ext_import_private_key_usage_period*(ext: ptr gnutls_datum_t;
    activation: ptr time_t; expiration: ptr time_t): cint {.
    importc: "gnutls_x509_ext_import_private_key_usage_period", gnutls_import.}
proc gnutls_x509_ext_export_private_key_usage_period*(activation: time_t;
    expiration: time_t; ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_private_key_usage_period", gnutls_import.}
proc gnutls_x509_ext_import_basic_constraints*(ext: ptr gnutls_datum_t;
    ca: ptr cuint; pathlen: ptr cint): cint {.importc: "gnutls_x509_ext_import_basic_constraints",
                                       gnutls_import.}
proc gnutls_x509_ext_export_basic_constraints*(ca: cuint; pathlen: cint;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_basic_constraints",
                                 gnutls_import.}
type
  gnutls_x509_key_purposes_st = object
  gnutls_x509_key_purposes_t* = ptr gnutls_x509_key_purposes_st

proc gnutls_x509_key_purpose_init*(p: ptr gnutls_x509_key_purposes_t): cint {.
    importc: "gnutls_x509_key_purpose_init", gnutls_import.}
proc gnutls_x509_key_purpose_deinit*(p: gnutls_x509_key_purposes_t) {.
    importc: "gnutls_x509_key_purpose_deinit", gnutls_import.}
proc gnutls_x509_key_purpose_set*(p: gnutls_x509_key_purposes_t; oid: cstring): cint {.
    importc: "gnutls_x509_key_purpose_set", gnutls_import.}
proc gnutls_x509_key_purpose_get*(p: gnutls_x509_key_purposes_t; idx: cuint;
                                 oid: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_key_purpose_get", gnutls_import.}
proc gnutls_x509_ext_import_key_purposes*(ext: ptr gnutls_datum_t;
    a2: gnutls_x509_key_purposes_t; flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_key_purposes", gnutls_import.}
proc gnutls_x509_ext_export_key_purposes*(a1: gnutls_x509_key_purposes_t;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_key_purposes",
                                 gnutls_import.}
proc gnutls_x509_ext_import_key_usage*(ext: ptr gnutls_datum_t; key_usage: ptr cuint): cint {.
    importc: "gnutls_x509_ext_import_key_usage", gnutls_import.}
proc gnutls_x509_ext_export_key_usage*(key_usage: cuint; ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_key_usage", gnutls_import.}
proc gnutls_x509_ext_import_inhibit_anypolicy*(ext: ptr gnutls_datum_t;
    skipcerts: ptr cuint): cint {.importc: "gnutls_x509_ext_import_inhibit_anypolicy",
                              gnutls_import.}
proc gnutls_x509_ext_export_inhibit_anypolicy*(skipcerts: cuint;
    ext: ptr gnutls_datum_t): cint {.importc: "gnutls_x509_ext_export_inhibit_anypolicy",
                                 gnutls_import.}
proc gnutls_x509_ext_import_proxy*(ext: ptr gnutls_datum_t; pathlen: ptr cint;
                                  policyLanguage: cstringArray;
                                  policy: cstringArray; sizeof_policy: ptr csize): cint {.
    importc: "gnutls_x509_ext_import_proxy", gnutls_import.}
proc gnutls_x509_ext_export_proxy*(pathLenConstraint: cint;
                                  policyLanguage: cstring; policy: cstring;
                                  sizeof_policy: csize; ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_proxy", gnutls_import.}
type
  gnutls_x509_policies_st = object
  gnutls_x509_policies_t* = ptr gnutls_x509_policies_st

proc gnutls_x509_policies_init*(a1: ptr gnutls_x509_policies_t): cint {.
    importc: "gnutls_x509_policies_init", gnutls_import.}
proc gnutls_x509_policies_deinit*(a1: gnutls_x509_policies_t) {.
    importc: "gnutls_x509_policies_deinit", gnutls_import.}
proc gnutls_x509_policies_get*(policies: gnutls_x509_policies_t; seq: cuint;
                              policy: ptr gnutls_x509_policy_st): cint {.
    importc: "gnutls_x509_policies_get", gnutls_import.}
proc gnutls_x509_policies_set*(policies: gnutls_x509_policies_t;
                              policy: ptr gnutls_x509_policy_st): cint {.
    importc: "gnutls_x509_policies_set", gnutls_import.}
proc gnutls_x509_ext_import_policies*(ext: ptr gnutls_datum_t;
                                     policies: gnutls_x509_policies_t;
                                     flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_policies", gnutls_import.}
proc gnutls_x509_ext_export_policies*(policies: gnutls_x509_policies_t;
                                     ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_policies", gnutls_import.}
proc gnutls_x509_ext_import_tlsfeatures*(ext: ptr gnutls_datum_t;
                                        a2: gnutls_x509_tlsfeatures_t;
                                        flags: cuint): cint {.
    importc: "gnutls_x509_ext_import_tlsfeatures", gnutls_import.}
proc gnutls_x509_ext_export_tlsfeatures*(f: gnutls_x509_tlsfeatures_t;
                                        ext: ptr gnutls_datum_t): cint {.
    importc: "gnutls_x509_ext_export_tlsfeatures", gnutls_import.}
proc gnutls_x509_tlsfeatures_add*(f: gnutls_x509_tlsfeatures_t; feature: cuint): cint {.
    importc: "gnutls_x509_tlsfeatures_add", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
