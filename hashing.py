""" Hashing Exercise

This is a short exercise to demonstrate some common hashing functions. Hashing is used throughout
cryptography whenever you need either a fingerprint of a file or some data, or if you need to store
something like a password in a way that the process can't be reversed.

Tasks:
1) Use SHA1, SHA-256 and SHA-512 and examine their output in HEX form
2) Use SHA-256 to hash the entire works of shakespeare into a single 256-bit summary!

To complete this exercise, read through the document filling in the necessary missing
code. If you need a code reference, you will find it here:

https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#module-cryptography.hazmat.primitives.hashes

"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import b16encode
backend = default_backend()

# First we'll create some hash objects that will perform the hashing:
sha1 = hashes.Hash(hashes.SHA1(), backend)
sha256 = hashes.Hash(hashes.SHA256(), backend)
sha512 = hashes.Hash(hashes.SHA512(), backend)

### Task 1 ###
# Hash the following message using SHA-1, SHA-256 and SHA-512.
# To make things a bit easier, SHA-1 has been done for you:
message = b'A message to be hashed'
sha1.update(message)
sha1hash = sha1.finalize()
if sha1hash != None:
    print ("SHA-1:", b16encode(sha1hash))

# Repeat this process for SHA-256
sha256.update(message)
sha256hash = sha256.finalize()
if sha256hash != None:
    print ("SHA-256:", b16encode(sha256hash))

# And SHA-512
sha512.update(message)
sha512hash = sha512.finalize()
if sha512hash != None:
    print ("SHA-512:", b16encode(sha512hash))


### Task 2 ###
# Hash the entire works of shakespeare using SHA-256! For convenience, I have loaded the file for you, you simply
# need to update the hash function with each 64-byte block

# Initialise new hashing function, you can't use the one from above that has been used and finalized
sha256 = hashes.Hash(hashes.SHA256(), backend)

with open('./data/shakespeare.txt', 'rb') as f:
    data = f.read(64)
    while data != b"":
        # Update the hash value here using data.
        sha256.update(data)
        # Read the next lock
        data = f.read(64)

# Finalise the hash
shakespeareHash = sha256.finalize()
if shakespeareHash != None:
    print ("Shakespeare SHA-256:", b16encode(shakespeareHash))