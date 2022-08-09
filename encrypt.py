from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from os import urandom
from os.path import exists
import sys

if sys.argv[1] == None:

    filename = input("enter filename: ")
    while not exists(filename):
        print("file does not exist.")
        filename = input("enter filename: ")
else:
    filename = sys.argv[1]

while True:
    key = input("enter your desired password: ")
    key2 = input("enter your desired password again: ")
    if key == key2:
        break

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
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**20,
    r=8,
    p=1,
    )

kdf.verify(key2.encode(), key) #verifies password
# encrypt 
nonce = urandom(32)
with open("nonce.txt", 'wb') as file:
    file.write(nonce)

chacha = ChaCha20Poly1305(key)
with open(filename, 'rb') as file:
    content = file.read()
encrypted = chacha.encrypt(nonce, content, None)
with open(filename, 'wb') as file:
    file.write(b64encode(encrypted))

print("encryption successfull")