""" Diffie-Hellman key exchange exercise

In this exercise you will communicate with a server and perform a diffie-hellman
key exchange. Normally this would be done over a network, but in this case we will
simluate the experience with a local class DHServer. This class is already implemented.

Tasks:
1) Generate a private key using the parameters obtained from the server
2) Create a public key based on the private key and send it to the server
3) Combine the server public and our private keys into a shared secret
4) Use AES CTR to decrypt a message from the server

Extra) ecdhkeyexchange.py is an equivalent file that performs elliptic-curve diffie-hellman.
For extra practice you can complete this as well.


To complete this exercise, read through the document filling in the necessary missing
code. If you need a code reference, you will find it here:

https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/#diffie-hellman-key-exchange

You will also find lots of helpful code in the DHServer implementation!

"""

import sys
sys.path.append(".")
sys.path.append("..")
from asymmetric import DHServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

server = DHServer()

# Obtain parameters from the server - this would normally come over a network
parameters = server.get_parameters()

# Obtain servers public DH key - also normally over a network
server_public_key = server.get_public_key()
print ("The server's public key is: ", server_public_key.public_numbers().y)

### Task 1 ###
# Generate your own private key (look at DHServer get_public_key for hints)
private_key = parameters.generate_private_key()
if private_key != None:
    print ("Our private key is: ", private_key.private_numbers().x)

### Task 2 ###
# Create a public key and send to the server  (look at DHServer get_public_key for hints)
public_key = private_key.public_key()
if public_key != None:
    print ("Our public key is: ", public_key.public_numbers().y)
server.submit_key(public_key)

### Task 3 ###
# Calculate the shared key for ourselves (look at DhServer submit_key for hints)
shared_key = private_key.exchange(server_public_key)
if shared_key != None:
    print ("Our shared key is: ", shared_key)

# At this point, our and the server's shared keys should be identical!

# It's normal to derive an actual encryption key from the master secret produced during the key
# exchange, rather than use it directly. The server does this, and returns an encrypted
# message:
data = server.get_encrypted_message()
iv = data["IV"]
ciphertext = data["Ciphertext"]

# Next we use the HKDF function to obtain a shared key, we haven't covered hashing yet,
# so this bit is done for you
if not shared_key: exit()
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'dhexercise', backend=default_backend())
aes_key = hkdf.derive(shared_key)

### Task 4 ###
# Use AES CTR mode to decrypt the server's message with the aes_key, this is the same key the server will
# have derived using your shared_key from the exchange
cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
decryptor = cipher.decryptor()
message = decryptor.update(ciphertext) + decryptor.finalize()

if message != None:
    print (message.decode("UTF-8"))
