""" Elliptic Curve Diffie-Hellman key exchange exercise

This is an optional exercise once you've completed dhkeyexchange.py

Tasks:
1) Generate a private key using the curve parameters obtained from the server
2) Create a public key based on the private key and send it to the server
3) Combine the server public and our private keys into a shared secret
4) Use HKDF to generate an aes key
5) Use AES CTR to decrypt a message from the server

To complete this exercise, read through the document filling in the necessary missing
code. If you need a code reference, you will find it here:

https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm

You will also find lots of helpful code in the ECDHServer implementation!

"""

import sys
sys.path.append(".")
sys.path.append("..")
from asymmetric import ECDHServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

server = ECDHServer()

# Obtain parameters from the server and their public key
curve = server.get_parameters()
server_public_key = server.get_public_key()
print ("The server's public key is: ", server_public_key.public_numbers().x, server_public_key.public_numbers().y)

### Task 1 ###
# Generate your own private key (look at ECDHServer get_public_key for hints, the format is slightly different to DH)
private_key = ec.generate_private_key(curve, default_backend())
if private_key != None:
    print ("Our private key is: ", private_key.private_numbers().private_value)

### Task 2 ###
# Create a public key and send to the server  (look at ECDHServer get_public_key for hints)
public_key = private_key.public_key()
if public_key != None:
    print ("Our public key is: ", public_key.public_numbers().x, public_key.public_numbers().y)
server.submit_key(public_key)

### Task 3 ###
# Calculate the shared key for ourselves (look at ECDHServer submit_key for hints)
shared_key = private_key.exchange(ec.ECDH(), server_public_key)
if shared_key != None:
    print ("Our shared key is: ", shared_key)

# Obtain encrypted message from the server
data = server.get_encrypted_message()
iv = data["IV"]
ciphertext = data["Ciphertext"]
if shared_key == None: exit()


### Task 4 ###
# Use HKDF to convert the shared key into an aes key
# This HKDF uses Sha256, Length 32 (256 bits), no salt, 'ecdhexercise' info.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecdhexercise', backend=default_backend())
aes_key = hkdf.derive(shared_key)

### Task 5 ###
# Use AES CTR to decrypt the message with the IV and aes key
cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
decryptor = cipher.decryptor()
message = decryptor.update(ciphertext) + decryptor.finalize()

if message != None:
    print (message.decode("UTF-8"))
