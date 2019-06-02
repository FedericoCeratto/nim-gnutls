let
  privKey = readFile("key.pk8").parsePKCS8PrivateKey()
  cert = readFile("cert.x509.pem").decodePEM().parseX509Cert()
  message = "A quick brown fox jumps over the lazy dog"
  signature = signPKCS7Detached(message, cert, privKey)

if keyType(privKey) == RSAKey:
  writeFile("signature.rsa", signature)
elif keyType(privKey) == ECDSAKey:
writeFile("signature.ec", signature)
