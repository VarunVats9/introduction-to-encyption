from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, NoEncryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

class RSAServer:
    def __init__(self):

        # This example RSA server uses a stored private key, rsa_private.pem. This server will sign documents or bytes
        # that you give it.
        # If you need to generate your own RSA key pair, it can be done like this:
        # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        # s = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        # with open('rsa_private.pem', 'wb') as outfile:
        #     outfile.write(s)
        # Notice it uses a public exponent of 65537. This is the most common choice for the public e.
        # The public key is the pair (n, e) where n is the large semi-prime.

        # Calculate local path to PEM file
        import os.path
        pem_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')

        # Load PEM file - a standard format for cryptographic keys and numbers.
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(pem_path, 'r') as f:
            pem_data = f.read().encode("UTF-8")
            private_key = load_pem_private_key(data=pem_data, backend=default_backend(), password=None)

        self.private_key = private_key
        self.public_key = private_key.public_key()

    # Sign a message using SHA-256 and PSS padding. By signing using it's private key, tied to the public key
    # we already have this server verifies its identity
    def sign_document(self, message):
        hash_function = hashes.SHA256()
        padding_scheme = padding.PSS(mgf=padding.MGF1(hash_function),salt_length=padding.PSS.MAX_LENGTH)
        signature = self.private_key.sign(message, padding_scheme,hashes.SHA256())
        return signature

    # We can encrypt a message using the server's public key, then submit it here. The server is the only one
    # who can read this message, by decrypting using its private key.
    def submit_message(self, ciphertext):
        if ciphertext == None:
            return

        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
            )
        )
        print ("The server decrypted your message as:", plaintext.decode("UTF-8"))