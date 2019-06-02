

when defined(windows):
  const libgnutls_fn* = "libgnutls.dll"
elif defined(macosx):
  const libgnutls_fn* = "libgnutls.dylib"
else:
  const libgnutls_fn* = "libgnutls.so(.18|.30)"

{.pragma: gnutls_import, importc, dynlib: libgnutls_fn.}

type
  api_cipher_hd_st* {.bycopy.} = object  # crypto
  dane_state_st* {.bycopy.} = object # dane
  gnutls_pkcs7_attrs_st* {.bycopy.} = object #pkcs7

  ssize_t* {.bycopy.} = object
  time_t* = cint

# TODO: too generic
proc `or`*[T](a, b: T): T =
  T(a.int or b.int)
