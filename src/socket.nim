import common
{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}
import gnutls
from winlean import SockAddr
##
##  Copyright (C) 2016 Free Software Foundation, Inc.
##
##  Author: Tim Ruehsen
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
##  This file contains socket related types, prototypes and includes.
##

##  Get socklen_t

##  *INDENT-OFF*

##  *INDENT-ON*

type socklen_t = cuint

proc gnutls_transport_set_fastopen*(session: gnutls_session_t; fd: cint;
                                   connect_addr: ptr Sockaddr;
                                   connect_addrlen: socklen_t; flags: cuint) {.
    importc: "gnutls_transport_set_fastopen", gnutls_import.}
##  *INDENT-OFF*

##  *INDENT-ON*
