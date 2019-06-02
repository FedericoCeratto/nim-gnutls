import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
##
##  Copyright (C) 2011-2012 Free Software Foundation, Inc.
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

const
  GNUTLS_COOKIE_KEY_SIZE* = 16

proc gnutls_dtls_set_timeouts*(session: gnutls_session_t; retrans_timeout: cuint;
                              total_timeout: cuint) {.
    importc: "gnutls_dtls_set_timeouts", gnutls_import.}
proc gnutls_dtls_get_mtu*(session: gnutls_session_t): cuint {.
    importc: "gnutls_dtls_get_mtu", gnutls_import.}
proc gnutls_dtls_get_data_mtu*(session: gnutls_session_t): cuint {.
    importc: "gnutls_dtls_get_data_mtu", gnutls_import.}
proc gnutls_dtls_set_mtu*(session: gnutls_session_t; mtu: cuint) {.
    importc: "gnutls_dtls_set_mtu", gnutls_import.}
proc gnutls_dtls_set_data_mtu*(session: gnutls_session_t; mtu: cuint): cint {.
    importc: "gnutls_dtls_set_data_mtu", gnutls_import.}
proc gnutls_dtls_get_timeout*(session: gnutls_session_t): cuint {.
    importc: "gnutls_dtls_get_timeout", gnutls_import.}
## *
##  gnutls_dtls_prestate_st:
##  @record_seq: record sequence number
##  @hsk_read_seq: handshake read sequence number
##  @hsk_write_seq: handshake write sequence number
##
##  DTLS cookie prestate struct.  This is usually never modified by
##  the application, it is used to carry the cookie data between
##  gnutls_dtls_cookie_send(), gnutls_dtls_cookie_verify() and
##  gnutls_dtls_prestate_set().
##

type
  gnutls_dtls_prestate_st* {.bycopy.} = object
    record_seq*: cuint
    hsk_read_seq*: cuint
    hsk_write_seq*: cuint


proc gnutls_dtls_cookie_send*(key: ptr gnutls_datum_t; client_data: pointer;
                             client_data_size: csize;
                             prestate: ptr gnutls_dtls_prestate_st;
                             `ptr`: gnutls_transport_ptr_t;
                             push_func: gnutls_push_func): cint {.
    importc: "gnutls_dtls_cookie_send", gnutls_import.}
proc gnutls_dtls_cookie_verify*(key: ptr gnutls_datum_t; client_data: pointer;
                               client_data_size: csize; msg: pointer;
                               msg_size: csize;
                               prestate: ptr gnutls_dtls_prestate_st): cint {.
    importc: "gnutls_dtls_cookie_verify", gnutls_import.}
proc gnutls_dtls_prestate_set*(session: gnutls_session_t;
                              prestate: ptr gnutls_dtls_prestate_st) {.
    importc: "gnutls_dtls_prestate_set", gnutls_import.}
proc gnutls_record_get_discarded*(session: gnutls_session_t): cuint {.
    importc: "gnutls_record_get_discarded", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
