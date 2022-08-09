from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from base64 import b64decode
from os.path import exists
import sys

def create_key():
    key = input("enter your password: ")
    while True:
        # derive
        
        salt = b"This salts your password by appending it to your set password and therefore you arbitrarly increase the size of your passwort, making it harder to attack your password hash with rainbowtables unless the salt is known to the attacker. In this case however, just change your password and this sentence."

        # increase n to increase safety, GROWS VERY FAST!! dont go overboard
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**20,
            r=8,
            p=1,
            )

        key = kdf.derive(key.encode())
        return key
if sys.argv[1] == None:
    filename = input("enter filename: ")
    while not exists(filename):
        print("file does not exist.")
        filename = input("enter filename: ")
else: 
    filename = sys.argv[1]

chacha = ChaCha20Poly1305(create_key())
with open(filename, 'rb') as file:
    content = b64decode(file.read())

with open("nonce.txt", "rb") as file:
    nonce = file.read()

while True:
    try:  
        decrypted = chacha.decrypt(nonce, content, None)
        break
    except Exception: 
        # happens if password is not correct
        print("wrong password")
        chacha = ChaCha20Poly1305(create_key())

with open(filename, 'wb') as file:
    file.write(decrypted)

print("decryption successfull")