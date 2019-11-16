from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ECDHServer:
    def __init__(self):

        # This example DH server uses a known elliptic curve. NIST P-256. This curve is used often
        # on the web to secure TLS messages. There is some controversy around it, with suggestions
        # of NSA involvement (!) but my strong suspicion is it's fine for normal use. If you are
        # overly cautious, use X25519.

        # Unlike standard DH, it is strongly recommended you don't generate your own curves.
        self.curve = ec.SECP256R1()
        self.shared_key = None

    # Return DH parameters (prime and generator)
    def get_parameters(self):
        return self.curve

    # Generate a new private key (a random number) and produce the public key based on this and the parameters.
    def get_public_key(self):
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()
        return self.public_key

    # Receive another public key as part of a handshake, and use it to calculate a share secret
    def submit_key(self, pk):
        if pk == None:
            return

        self.shared_key = self.private_key.exchange(ec.ECDH(), pk)
        print("The server's shared key is: ", self.shared_key)

    def get_encrypted_message(self):
        if not self.shared_key:
            return { "IV": "", "Ciphertext": "" }

        # Derive the key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        hkdf = HKDF(algorithm = hashes.SHA256(), length = 32, salt = None, info = b'ecdhexercise', backend = default_backend())

        from os import urandom
        IV = urandom(16)
        aes_key = hkdf.derive(self.shared_key)

        """
        Single block AES in CTR mode. Use a new random IV and return this as well.
        """
        message = b'\x87\x95\x9c\x9cP\x94\x9f\x9e\x95QP\x89\x9f\xa5W\xa6\x95P\x93' \
                  b'\x9f\x9d\xa0\x9c\x95\xa4\x95\x94P\xa4\x98\x95P\x95\xa8\xa4' \
                  b'\xa2\x91P\x95\xa8\x95\xa2\x93\x99\xa3\x95P\x91\x9e\x94P\xa0' \
                  b'\x95\xa2\x96\x9f\xa2\x9d\x95\x94P\x91\x9ePustxP\x95\xa8\x93' \
                  b'\x98\x91\x9e\x97\x95P\xa5\xa3\x99\x9e\x97P\xa4\x98\x95P~y' \
                  b'\x83\x84P\x80]befPs\xa5\xa2\xa6\x95Q'

        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(IV), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes([b - 48 % 255 for b in message])) + encryptor.finalize()
        return { "IV": IV, "Ciphertext": ciphertext }