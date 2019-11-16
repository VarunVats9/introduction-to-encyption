""" RSA Public-Key Exercise

In this exercise you will use RSA to verify a signed message, and to encrypt another
message that only a server can read.

Although RSA can be used by a client for authentication, it's most commonly used to
verify the identity of a server, as we are doing here.

Tasks:
1) Given a message of your choosing, verify a signature obtained from the server.
2) Use a server's public key to encrypt a message only it can read.

General documentation here:

https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#module-cryptography.hazmat.primitives.asymmetric.rsa

More specific documentation is contained below.

"""
import os
import sys
sys.path.append(".")
sys.path.append("..")
from asymmetric import RSAServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# This server mimics one over the internet, e.g. in a TLS handshake
server = RSAServer()

# Load server public key. Usually this key would be found in a certificate, either passed from the server and
# signed by a certificate authority, or stored on your machine as a root certificate.
from cryptography.hazmat.primitives.serialization import load_pem_public_key
with open(os.path.join(os.path.dirname(__file__), '../data/rsa_public.pem'), 'r') as f:
    pem_data = f.read().encode("UTF-8")
    public_key = load_pem_public_key(data=pem_data, backend=default_backend())

### Task 1 ###
# If a server signs a message with its private key, we can verify with its public key.
# First choose a message and have the server sign it:
message = b"Insert your verification message here"
signed_message = server.sign_document(message)

# To sign the message, the server will encrypt a hash of it using its private key, we can repeat this process
# and verify it with the public key

try:
    # Verify the signed message using public_key.verify()
    # Documentation here: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
    # For padding, use PSS with MGF1-SHA256 as per the documentation

    # Verify will raise an exception if the signature fails. Replace this line with a verification:
    public_key.verify(
        signed_message,
        message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print ("The server successfully signed the message.")
except InvalidSignature:
    print("The server failed our signature verification!")

### Task 2 ###
# Encrypt a message using the server's public key, so that only the server can read it
# Documentation here: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
# For padding, use OAEP with MGF1-SHA1 as per the documentation (but with SHA-256)
message = b"Insert your secret message here"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("The encrypted message is:", ciphertext)

# Submit the ciphertext to the server, which will attempt to output the decrypted version.
server.submit_message(ciphertext)