import base64
from Crypto.Cipher import AES
msg_text = 'test some plain text here'.rjust(32)
secret_key = '1614567790183496' # create new & store somewhere safe

cipher = AES.new(secret_key,AES.MODE_ECB)
encoded = base64.b64encode(cipher.encrypt(msg_text))

print(encoded.decode('UTF-8'))
encoded = base64.b64encode(cipher.encrypt(msg_text))
print(encoded.decode('UTF-8'))
# ...
decoded = cipher.decrypt(base64.b64decode(encoded))
print(decoded.decode('UTF-8'))