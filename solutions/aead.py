""" Authenticated Encryption with Additional Data (AEAD) Exercise

In this exercise you will gain experience using AEAD modes of encryption. In this scenario
we have a fictitious database record that we wish to store in encrypted format. Your task
will be to write the two functions that perform the encryption and decryption.

Tasks:
1) Implement the encrypt_record() function, to take a supplied record and encrypt any sensitive
information. The function must use AEAD to also authenticate all other additional data.
2) Implement the decrypt_record() function, to take an encrypted record and decrypt it. Any
changes to any records will be caught by the AEAD tag check.

To complete this exercise, read through the document filling in the necessary missing
code. More detailed instructions are found below, alongside each function.

You can use either AES-GCM or ChaChaPoly1305 for this task. Code references can be found
here:

https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305

Both use exactly the same encrypt and decrypt functions. They support differing key and IV sizes, but the ones below
will work with either.

"""

import os
import json  # JSON is used here only for nicely formatted print output, you can ignore it.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# This is our fictitious database record. For this exercise, this is just a local object, but could just as easily
# be stored in a real database.
record = {
    "ID": "0054",
    "Surname": "Smith",
    "FirstName": "John",
    "JoinDate": "2016-03-12",
    "LastLogin": "2017-05-19",
    "Address": "5 Mornington Crescent, London, WN1 1DA",
    "Nationality": "UK",
    "DOB": "1963-09-14",
    "SSN": "QQ123456C",
    "Phone": "01224103232",
    "Data": None,
    "Nonce": None,
}

### Task 1 ###
# Implement this function to take a record, and encrypt it using an AEAD cipher. You must adhere to the following:
#  - ID, Surname, Firstname, JoinDate, Lastlogin are not confidential, but must be authenticated as additional data
#  - Address, Nationality, DOB, SSN, Phone are confidential, and must be encrypted
#  - Additional data fields must remain unchanged in the record.
#  - Encrypted fields must be set to None, with "Data" and "Nonce" populated by the ciphertext and nonce used.
def encrypt_record(record, key, nonce):

    # Combine confidential fields into a plaintext value
    # Hints: Try appending the fields together using a delimiter, e.g. "\x1f" which is the ascii "unit separator"
    # You'll also need to convert your string into bytes using data.encode("UTF-8")
    plaintext = '\x1f'.join(
        [v for k, v in record.items() if k in ['Address', 'Nationality', 'DOB', 'SSN', 'Phone']]
    ).encode("UTF-8")

    # Perform the same process for the authenticated fields, those that aren't encrypted
    ad = '\x1f'.join([v for k, v in record.items() if
                   k in ['ID', 'Surname', 'FirstName', 'JoinDate', 'LastLogin']]
    ).encode("UTF-8")

    # Create an aead cipher and encrypt to produce the ciphertext
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad)

    # Set the encrypted records to None, leave the authenticated ones, and set data to be the ciphertext
    record.update({
        "Address": None,
        "Nationality": None,
        "DOB": None,
        "SSN": None,
        "Phone": None,
        "Data": ciphertext,
        "Nonce": nonce,
    })

### Task 2 ###
# Implement this function to take a record, and decrypt it using the same AEAD cipher. You must adhere to the following:
#  - ID, Surname, Firstname, JoinDate, Lastlogin must be re-supplied as the additional data, in the exact same format
#  - Address, Nationality, DOB, SSN, Phone must be decrypted, split, and restored into the fields of the record
#  - Data and Nonce should be set back to None
def decrypt_record(record, key):

    # Combine the authenticated fields into an identical ad object as in the encryption function
    ad = '\x1f'.join([v for k, v in record.items() if
                   k in ['ID', 'Surname', 'FirstName', 'JoinDate', 'LastLogin']]).encode("UTF-8")

    # Create an aead cipher and decrypt the ciphertext into the plaintext
    # Hints: You'll need to use the record["Nonce"] and record["Data"] fields
    # You'll need to decode the bytes into a string using plaintext.decode("UTF-8")
    # You'll also need to undo the string concatenation with a delimiter using .split('\x1f') for your delimiter
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(record["Nonce"], record["Data"], ad).decode("UTF-8").split('\x1f')

    # Re-populate the record with the decrypted fields, and set data / nonce back to None
    record.update({
        "Address": plaintext[0],
        "Nationality": plaintext[1],
        "DOB": plaintext[2],
        "SSN": plaintext[3],
        "Phone": plaintext[4],
        "Data": None,
        "Nonce": None,
    })

# The code below makes use of your functions, you do not need to change it. Valid records should be output to the
# terminal when the code is run

# Random key and nonce. When encrypting database records we would usually also encrypt this key with a key encryption
# key, but we won't this time.
key = os.urandom(16)
nonce = os.urandom(12)

# Encrypt the record and show the output on the screen. All confidential fields should be "None" at this point
encrypt_record(record, key, nonce)
print("Encrypted Record:\n{")
for k,v in record.items():
    print(" ", k, ":", v)
print("}")

# Decrypt the record and show the output on the screen. All confidential fields should be restored
decrypt_record(record, key)
print("Decrypted Record\n{")
for k,v in record.items():
    print(" ", k, ":", v)
print("}")