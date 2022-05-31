from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from base64 import b64encode

def create_key():
    key = input("enter your password: ")
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
        if len(derived_password) % 2 == 0:
            __derived_password__ = "0"
            return aes_key
        key = input("enter your  c o r r e c t  password: ") # password cannot be correct.


filename = input("enter filename: ")
aes_key = create_key()

# decrypt 
fernet = Fernet(b64encode(aes_key))

with open(filename, 'rb') as file:
    content = file.read()

while True:
    try:  
        decrypted = fernet.decrypt(content)
        break
    except Exception: # happens if password is not correct
        print("wrong password")
        fernet = Fernet(b64encode(create_key()))

with open(filename, 'wb') as file:
    file.write(decrypted)

print("decryption successfull")