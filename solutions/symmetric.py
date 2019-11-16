""" Symmetric Cryptography Exercise

In this exercise you will use AES to encrypt and decrypt some messages. AES can be
applied in a number of modes. These include Electronic Code Book (ECB), cipher block
chaining (CBC) and counter mode (CTR).

Tasks:
1) Use AES-CBC to encrypt then decrypt a single block of data
2) Use AES-CTR to decrypt a longer message for which you already have the ciphertext.

ECB mode has been implemented for you, your task is to finish off CBC and CTR modes!

To complete this exercise, read through the document filling in the necessary missing
code. If you need a code reference, you will find it here:

https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher

"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

# Initlalise a new 128 bit key
key = os.urandom(16)

# This is a one block message we can encrypt. One AES block is 128 bits.
message = b"a secret message"

# Initialise the cipher in ECB mode, and use the encryptor and decryptor interfaces
# to encrypt and decrypt the ciphertext
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

# Encryption
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()

# Decryption
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print ("-- ECB --")
print ("Ciphertext is:", ciphertext)
print ("Plaintext is:", plaintext)

### Task 1 ###
# Now it's your turn! CBC uses a similar interface to ECB, except that it requires both a key, and an iv
# Initialise these randomly now. Make the key 32 bytes and the IV 16 bytes.
key = os.urandom(32)
iv = os.urandom(16)

# Now fill in the code here to encrypt the same message as ECB, remember to use the CBC.
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print ("-- CBC --")
print ("Ciphertext is:", ciphertext)
print ("Plaintext is:", plaintext)

### Task 2 ###
# Last we'll look at CTR mode. This mode converts a block cipher into
# a stream cipher. This means that CTR mode neatly handles messages that
# are not a multiple of the block length without needing padding.

# Here is just such a message, that's already been encrypted:
ciphertext = b'\xb8\xbf\xa0$~\xbe\x87*\x86\x18\xa4g' \
             b'\xd4=MAt\xd8X\x95<?>\xa2r\x04;{@\x8c' \
             b'\xab!\rC\xb3\x0e\x10\xa9\t;\x83\xce|'
key = b'\xfa\t\xc6\xdd\xac\xb0a\x99\xef]{`\x07\xe7\xbf\xee'
iv = b'P\xbe\xd9\x04\xd00;4\xf9\xeb^\x0f3\x16\xfb\xa3'

# Create a cipher here to decrypt the ciphertext using CTR mode.
# No partially completed cipher code this time!
cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print ("-- CTR --")
print ("Ciphertext is:", ciphertext)
print ("Plaintext is:", plaintext)
