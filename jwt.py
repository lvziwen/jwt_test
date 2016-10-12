import base64
import json
import hashlib

header = {
  "alg": "HS256",
  "typ": "JWT"
}

payload = {
  "sub": "1234567890",
  "name": "John Doe",
  "admin": True
}

secret = "hayao_test_jwt"


###encode jwt
header_str = json.dumps(header)
payload_str = json.dumps(payload)

header_b64 = base64.urlsafe_b64encode(header_str)
payload_b64 = base64.urlsafe_b64encode(payload_str)

sh = hashlib.sha256(secret)
sh.update(header_b64 + "." + payload_b64)
signature = sh.hexdigest()

jwt = header_b64 + "." + payload_b64 + "." + signature

print jwt


###decode jwt
(header_b64_jwt, payload_b64_jwt, signature_jwt) = jwt.split(".")

sh = hashlib.sha256(secret)
sh.update(header_b64_jwt + "." + payload_b64_jwt)
signature_check = signature = sh.hexdigest()

if signature_jwt != signature_check:
    print "ERROR"
else:
    print "YES"
