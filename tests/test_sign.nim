import unittest

import gnutls
import x509
import abstract

import strutils


type GnuTLSError* = object of Exception

template check_rc(rc: cint): untyped =
  ## Expect return code to be 0, raise an exception otherwise
  if rc != 0:
    raise newException(GnuTLSError, $gnutls_strerror(rc))

template cpt(target: string): untyped =
  cast[ptr cuchar](cstring(target))

proc fromCString(p: pointer, len: int): string =
  result = newString(len)
  copyMem(result.cstring, p, len)

proc show(desc: string, p:pointer, len: cuint, raw = false) =
  if raw:
    echo desc & ": " & fromCString(p, len.int)
  else:
    echo desc & ": " & fromCString(p, len.int).toHex()

proc `$`(d: gnutls_datum_t): string =
  fromCString(d.data, d.size.int)

proc hex*(d: gnutls_datum_t): string =
  toHex($d)

proc hex2*(d: gnutls_datum_t): string =
  fromCString(d.data, d.size.int + 16).toHex()

proc compare(a, b: pointer, size: int): int =
  let x = fromCString(a, size)
  let y = fromCString(b, size)
  var diffs = ""
  for pos in 0..x.high:
    if x[pos] != y[pos]:
      result.inc
      diffs.add ($pos & " ")
  if diffs != "":
    echo diffs


# Test material - create directory 'tmp'
# openssl genrsa -out key.pem 1024
# openssl req -new -key key.pem -out request.pem
# openssl x509 -req -days 9999 -in request.pem -signkey key.pem -out certificate.pem
# openssl pkcs8 -topk8 -outform DER -in key.pem -inform PEM -out key.pk8 -nocrypt
# openssl pkcs8 -topk8 -in key.pem -inform PEM -out key.pem.pk8 -outform PEM -nocrypt

proc gnutls_new_datum*(s=""): gnutls_datum_t =
  result = gnutls_datum_t()
  result.data = cast[ptr cuchar](s)
  result.size = s.len.csize


suite "x509":

  test "datum":
    var datum = gnutls_new_datum("")
    check datum.size == 0.csize
    datum = gnutls_new_datum(" ")
    check datum.size == 1.csize
    check datum.hex2 == "0100000000000000010000000000004020"

  test "read encrypted privkey":
    const
      # this is PEM
      PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAiebBrnqPv4owICCAAw\nHQYJYIZIAWUDBAEqBBBykFR6i1My/DYFBYrz1lmABIGQ3XGpp3+v/ENC1S+X7Ay6\nJoquYKuMw6yUmWoGFvPIPA9UWqMve2Uj4l2l96Sywd6iNFP63ow6pIq4wUP6REuY\nZhCgoAOQomeFqhAhkw6QJCygp5vw2rh9OZ5tiP/Ko6IDTA2rSas91nepHpQOb247\nzta5XzXb5TRkBsVU8tAPADP+wS/vBCS05ne1wmhdD6c6\n-----END ENCRYPTED PRIVATE KEY-----\n"

    var data = gnutls_new_datum(PRIVATE_KEY)
    check data.hex2.endswith("0A")

    var pk: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr pk)

    var key: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr key)
    let err = gnutls_x509_privkey_import_pkcs8(key, addr(data), GNUTLS_X509_FMT_PEM, "", 0)
    check $gnutls_strerror(err) == "Decryption has failed."
    check_rc gnutls_x509_privkey_import_pkcs8(key, addr(data), GNUTLS_X509_FMT_PEM, "password", 0)
    gnutls_x509_privkey_deinit(key)

  test "read RSA privkey PEM not PK8":
    # openssl genrsa -out key.pem 1024
    const keyfn = "key.pem"
    var pkey: gnutls_x509_privkey_t
    assert pkey == nil
    check_rc gnutls_x509_privkey_init(addr pkey)
    assert pkey != nil
    var d = gnutls_datum_t()
    check_rc gnutls_load_file(keyfn, addr d)
    #show("pkey", pkey, 1024)

    # import key
    var key: gnutls_privkey_t
    check_rc gnutls_privkey_init(addr key)
    check_rc gnutls_privkey_import_x509(key, pkey, 0)
    #show("key", key, 1024)

    var key2: gnutls_privkey_t
    check_rc gnutls_privkey_init(addr key2)
    check_rc gnutls_privkey_import_x509_raw(key2, addr(d), GNUTLS_X509_FMT_PEM, nil, 0)
    #show("key2", key2, 1024)

    gnutls_x509_privkey_deinit(pkey)
    gnutls_privkey_deinit(key)
    gnutls_privkey_deinit(key2)

  test "read PEM PK8 privkey":
    const keyfn = "tmp/key.pem.pk8"
    var pkey: gnutls_x509_privkey_t
    assert pkey == nil
    check_rc gnutls_x509_privkey_init(addr pkey)
    assert pkey != nil
    var d = gnutls_datum_t()
    check_rc gnutls_load_file(keyfn, addr d)
    #show("key", d.data, d.size)
    check_rc gnutls_x509_privkey_import_pkcs8(pkey, addr(d), GNUTLS_X509_FMT_PEM, "", 0)
    gnutls_x509_privkey_deinit(pkey)

  test "read privkey DER PK8":
    # this is PKCS 8 DER unencrypted
    const keyfn = "tests/data/key.pk8"

    var pkey: gnutls_privkey_t
    check_rc gnutls_privkey_init(addr pkey)

    var data = gnutls_datum_t()
    check_rc gnutls_load_file(keyfn, addr data)  # DER
    check data.hex() == "3041020100301306072A8648CE3D020106082A8648CE3D030107042730250201010420AF36DB30152C58A3BDFCAD933CB5B40F4F9C0802A4879D741A5152BB2EF09BCF"

    # import key
    var key5: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr key5)

    # FIXME check_rc gnutls_x509_privkey_import_pkcs8(key5, addr(data), GNUTLS_X509_FMT_DER, "", 0)

    gnutls_x509_privkey_deinit(key5)

  test "sign":
    # Load cert in PEM format
    const certfn = "tests/data/cert.x509.pem"
    var certd: gnutls_datum_t
    check_rc gnutls_load_file(certfn, addr certd)

    var cert: gnutls_x509_crt_t
    assert cert == nil
    check_rc gnutls_x509_crt_init(addr cert)
    assert cert != nil
    check_rc gnutls_x509_crt_import(cert, addr certd, GNUTLS_X509_FMT_PEM);

    var o: gnutls_datum_t
    check_rc gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_ONELINE, addr o)
    check $o == """subject `0.1=#1300', issuer `0.1=#1300', serial 0x01, EC/ECDSA key 256 bits, signed using 0.1, activated `2017-10-10 22:50:00 UTC', expires `2017-10-10 22:50:00 UTC', pin-sha256="gxaAxH/hl3kesHXIFEDcZt6fMqFl+Rb01oY8QlZaqMQ=""""

    check_rc gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_COMPACT, addr o)
    # mind the tabs
    const expected = """subject `0.1=#1300', issuer `0.1=#1300', serial 0x01, EC/ECDSA key 256 bits, signed using 0.1, activated `2017-10-10 22:50:00 UTC', expires `2017-10-10 22:50:00 UTC', pin-sha256="gxaAxH/hl3kesHXIFEDcZt6fMqFl+Rb01oY8QlZaqMQ="
	Public Key ID:
		sha1:43047523567e781bc437d6e497b5befc4bcd10ff
		sha256:831680c47fe197791eb075c81440dc66de9f32a165f916f4d6863c42565aa8c4
	Public Key PIN:
		pin-sha256:gxaAxH/hl3kesHXIFEDcZt6fMqFl+Rb01oY8QlZaqMQ=
"""
    check $o == expected

    let algo = cert.gnutls_x509_crt_get_signature_algorithm()
    #echo $gnutls_sign_get_name(algo.gnutls_sign_algorithm_t)
    check GNUTLS_SIGN_UNKNOWN.cint == algo

    var sig = "".cstring
    var size = 0.csize
    #check_rc gnutls_x509_crt_get_signature(cert, sig, addr size) FIXME

    # import privkey
    const keyfn = "tmp/key.pem.pk8"
    var pkey: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr pkey)
    var d = gnutls_datum_t()
    check_rc gnutls_load_file(keyfn, addr d)
    check_rc gnutls_x509_privkey_import_pkcs8(pkey, addr(d), GNUTLS_X509_FMT_PEM, "", 0)

    # import privkey
    const
      # this is PEM
      PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAiebBrnqPv4owICCAAw\nHQYJYIZIAWUDBAEqBBBykFR6i1My/DYFBYrz1lmABIGQ3XGpp3+v/ENC1S+X7Ay6\nJoquYKuMw6yUmWoGFvPIPA9UWqMve2Uj4l2l96Sywd6iNFP63ow6pIq4wUP6REuY\nZhCgoAOQomeFqhAhkw6QJCygp5vw2rh9OZ5tiP/Ko6IDTA2rSas91nepHpQOb247\nzta5XzXb5TRkBsVU8tAPADP+wS/vBCS05ne1wmhdD6c6\n-----END ENCRYPTED PRIVATE KEY-----\n"
    var kdata = gnutls_new_datum(PRIVATE_KEY)
    var pk: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr pk)
    var key: gnutls_x509_privkey_t
    check_rc gnutls_x509_privkey_init(addr key)
    check_rc gnutls_x509_privkey_import_pkcs8(key, addr(kdata), GNUTLS_X509_FMT_PEM, "password", 0)

    var
      #signature = gnutls_new_datum(repeat('s', 1024))
      #signature_size: csize = 1024.csize
      text = gnutls_new_datum(repeat('d', 1024))

      signature: gnutls_datum_t = gnutls_datum_t()
      #signature_size: cint
      signature_size: csize = 1024.csize

    #echo repr signature.data
    #check_rc gnutls_x509_privkey_sign_data(
    #  key, GNUTLS_DIG_SHA1, 0.cuint, addr text, addr signature, addr signature_size)
    #signature.size = signature_size
    #echo repr signature.size
    #echo 333
    #echo repr signature.data
    #echo signature_size
    #echo 22
    #echo hex signature

    gnutls_x509_crt_deinit(cert)

  test "encrypt, decrypt":
    # Generate and verify private and public keys
    var privkey: gnutls_privkey_t
    check_rc gnutls_privkey_init(addr privkey)
    check_rc gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, 1024.cuint, 0.cuint)
    check_rc gnutls_privkey_verify_params(privkey)

    var
      plaintext = gnutls_new_datum("plain")
      ciphertext = gnutls_new_datum()


    #check_rc gnutls_pubkey_import_pkcs11(pubkey, obj, 0.cuint)

    # import pubkey
    var pubkey: gnutls_pubkey_t
    check_rc gnutls_pubkey_init(addr pubkey)
    const ANY_USE = 0.cuint
    check_rc gnutls_pubkey_import_privkey(pubkey, privkey, ANY_USE, 0.cuint)
    check_rc gnutls_pubkey_verify_params(pubkey)
    var usage: cuint
    check_rc gnutls_pubkey_get_key_usage(pubkey, addr usage)
    check usage == ANY_USE

    var pubkey2: gnutls_pubkey_t
    check_rc gnutls_pubkey_init(addr pubkey2)
    check_rc gnutls_pubkey_import_privkey(pubkey2, privkey, GNUTLS_KEY_DECIPHER_ONLY, 0.cuint)
    check_rc gnutls_pubkey_verify_params(pubkey2)
    #echo compare(pubkey, pubkey2, 1024)
    check_rc gnutls_pubkey_get_key_usage(pubkey2, addr usage)
    check usage == GNUTLS_KEY_DECIPHER_ONLY

    ##check_rc gnutls_pubkey_import_x509(pubkey, crt, 0.cuint)

    # encrypt
    check_rc gnutls_pubkey_encrypt_data(pubkey, 0.cuint, addr plaintext, addr ciphertext)
    check ciphertext.size == 128

    # sign
    var signature = gnutls_new_datum("")
    check_rc gnutls_privkey_sign_data2(privkey, GNUTLS_SIGN_RSA_PSS_SHA256, 0.cuint, addr plaintext, addr signature)

    # verify
    #check_rc gnutls_pubkey_verify_data2(pubkey, GNUTLS_PK_RSA_PSS.gnutls_sign_algorithm_t, 0.cuint, addr plaintext, addr signature)

    # decrypt
    var plaintext2 = gnutls_datum_t() # gnutls_new_datum("")
    check_rc gnutls_privkey_decrypt_data(privkey, 0.cuint, addr ciphertext, addr plaintext2)
    check plaintext.size == plaintext2.size
    check plaintext.size == 5

    check compare(plaintext.data, plaintext2.data, plaintext.size) == 0
    # FIXME
    #check plaintext.hex2 == plaintext2.hex2

    pubkey.gnutls_pubkey_deinit()
    privkey.gnutls_privkey_deinit()
