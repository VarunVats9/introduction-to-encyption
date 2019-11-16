from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class DHServer:
    def __init__(self):

        # This example DH server uses a known safe prime, or can generate its own if the PEM file is not available.
        # The safe prime used here is ffdhe2048, described here:
        # https://tools.ietf.org/html/rfc7919#appendix-A.1
        # There is nothing strictly wrong with generating your own prime, but this one is well tested.

        import os.path
        pem_path = os.path.join(os.path.dirname(__file__), 'dh_params.pem')
        if not os.path.isfile(pem_path):
            # No PEM file available, generate a new prime of 2048 bits.
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            s = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            with open('dh_params.pem', 'wb') as outfile:
                outfile.write(s)
        else:
            # Load PEM file - a standard format for cryptographic keys and numbers.
            from cryptography.hazmat.primitives.serialization import load_pem_parameters
            with open(pem_path, 'r') as f:
                pem_data = f.read().encode("UTF-8")
                parameters = load_pem_parameters(data=pem_data, backend=default_backend())
        self.parameters = parameters
        self.shared_key = None

    # Return DH parameters (prime and generator)
    def get_parameters(self):
        return self.parameters

    # Generate a new private key (a random number) and produce the public key based on this and the parameters.
    def get_public_key(self):
        self.privatekey = self.parameters.generate_private_key()
        self.public_key = self.privatekey.public_key()
        return self.public_key

    # Receive another public key as part of a handshake, and use it to calculate a share secret
    def submit_key(self, pk):
        if pk == None:
            return

        self.shared_key = self.privatekey.exchange(pk)
        print("The server's shared key is: ", self.shared_key)

    def get_encrypted_message(self):
        if not self.shared_key:
            return { "IV": "", "Ciphertext": "" }

        # Derive the key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        hkdf = HKDF(algorithm = hashes.SHA256(), length = 32, salt = None, info = b'dhexercise', backend = default_backend())

        from os import urandom
        IV = urandom(16)
        aes_key = hkdf.derive(self.shared_key)

        """
        Single block AES in CTR mode. Use a new random IV and return this as well.
        """
        # Message masked with a caesar cipher to make it a surprise!
        message = b"Iutmxgz{rgzouty2&\x7fu{-|k&y{iikyyl{r" \
                  b"r\x7f&yngxkj&g&jollok3nkrrsgt&qk\x7f2" \
                  b"&znkt&jkxo|kj&g&y\x7fsskzxoi&qk\x7f&g" \
                  b"tj&jkix\x7fvzkj&znoy&skyygmk'"
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(IV), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes([b - 6 % 255 for b in message])) + encryptor.finalize()
        return { "IV": IV, "Ciphertext": ciphertext }