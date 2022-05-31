from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from base64 import b64encode



filename = input("enter filename: ")
while True:

    key = input("enter your desired password: ")
    key2 = input("enter your desired password again: ")
    if key == key2:
        break
while True:
    # derive
    kdf = PBKDF2HMAC(
        algorithm=sha256(),
        salt=bytes(key, 'UTF_8'),
        length=32,
        iterations=10000,
        backend=default_backend()
    )

    aes_key = kdf.derive(key.encode())
    derived_password = hex(
        int.from_bytes(aes_key, 'big'))[2:]
    # check that there are no half bytes (can happen during derivation)
    # artifact from my project, but better safe than sorry.
    print("key generated")
    if len(derived_password) % 2 == 0:
        __derived_password__ = "0"
        break
kdf = PBKDF2HMAC(
    algorithm=sha256(),
    salt=bytes(key, 'UTF_8'),
    length=32,
    iterations=10000,
    backend=default_backend()
    )
kdf.verify(key.encode(), aes_key) #verifies password
# encrypt 
fernet = Fernet(b64encode(aes_key))
with open(filename, 'rb') as file:
    content = file.read()
encrypted = fernet.encrypt(content)
with open(filename, 'wb') as file:
    file.write(encrypted)

print("encryption successfull")