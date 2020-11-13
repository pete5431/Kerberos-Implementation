# The DES algorithm used is from the pycryptodome package.
from Crypto.Cipher import DES
import random
import string
import base64

"""
The pycryptodome package uses C language code. Therefore in order use strings with pycryptodome functions, bytes objects are used.
"""

class SecurityInfo:

    """
    Class that holds the infomration for ports, and host. Also contains encryption/decryption functions and keys.
    """

    HOST = '127.0.0.1'
    PORT = 54643
    PORT_K = 47578

    ID_TGS = "CIS3319TGSID"
    ID_V = "CIS3319SERVERID"
    ID_C = "CIS3319USERID"

    Lifetime2 = '60'
    Lifetime4 = '86400'

    DEFAULT_KEY = b'default_'

    def __init__(self, KEY = DEFAULT_KEY):
        """
        Constructor for ServerInfo.
            -Uses default values if none are provided.
        """
        self.DESKEY = KEY
        self.HMACKEY = KEY
        # DES object from pycryptodome used for DES encryption.
        self.DES = DES.new(self.DESKEY, DES.MODE_ECB)

    def read_des_key(self, filename):
        """
        Reads the des key from des_key.txt
            -Will read the first 8 bytes because key is 8-bytes.
        """
        key_file = open(filename, 'r')
        self.DESKEY = bytes(key_file.read(8), 'utf-8')
        self.DES = DES.new(self.DESKEY, DES.MODE_ECB)
        key_file.close()

    def set_des_key(self, key):
        self.DESKEY = key
        self.DES = DES.new(self.DESKEY, DES.MODE_ECB)

    def generate__des_key(self):
        """
        Generates a random key of size 8 with alphanumeric + special characters.
        """
        chars = string.ascii_letters + string.digits + string.punctuation;
        key_list = []
        for i in range(0,8):
            key_list.append(random.choice(chars))
        key = ''.join(key_list)
        return key

    def encrypt_message(self, plain_text):
        """
        Takes the plaintext and key and returns the DES encrypted ciphertext.
            -The DES algorithm is the one given by pycryptodome.
            -ECB mode is used.
            -Encodes resulting ciphertext with base64.
            -Encodes plaintext to bytes because of pycryptodome using C.
            -Expects plain_text to be a string argument.
            -Returned cipher_text is in bytes.
            -Uses PKCS5 padding to ensure message is multiple of 8.
            -Pads with byte that are the same value as the number of padding bytes to be added.
        """
        # Calculates the number of padding bytes required.
        pad_value = (8 - len(plain_text) % 8)
        # If 8, then the message is ok as is.
        if pad_value != 8:
            # Convert the padding value to ASCII and multiply by itself and append to message.
            plain_text += (pad_value * chr(pad_value))

        cipher_text = self.DES.encrypt(bytes(plain_text,'UTF-8'))
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text

    def decrypt_message(self, cipher_text):
        """
        Takes the ciphertext and key and returns the DES decrypted plaintext.
            -The DES algorithm is the one given by pycryptodome.
            -ECB mode is used.
            -Decodes base64 then uses decrypt function of the DES object.
            -Argument can be either bytes or string.
            -Returned plain_text is a string.
        """
        cipher_text = base64.b64decode(cipher_text)
        plain_text = self.DES.decrypt(cipher_text)
        return self.unpad_message(plain_text.decode('UTF-8'))

    def split_message(self, message):
        """
        Takes a string input with prepended lengths and fetches all components of the string and puts them in a list.
        """
        new_list = []
        part = ''
        index = 0
        while index != len(message):
            b_length = bytes(message[index:index+2], 'UTF-8')
            length = int.from_bytes(b_length, 'little')
            index += 2
            for c in message[index:index+length]:
                part += c
                index += 1
            new_list.append(part)
            part = ''
        return new_list

    def prepend_length(self, message):
        """
        Prepends the length of the message.
            -Max 2 bytes.
            -A max length of 65535 characters should be enough.
        """
        length = len(message)
        if length >= 65536:
            print("Error: length too large")
            return ''
        b_length = length.to_bytes(2, 'little')
        return b_length.decode('UTF-8') + message

    def unpad_message(self, message):
        """
        Unpads the message so that original message is obtained.
            -Checks the last value in the message, which will be the padding value if padding was added.
            -Then checks to make sure the count of the padding value matches the padding value.
        """
        # If length of message is zero. Return message.
        if(len(message) == 0):
            return message
        # Uses ord() to convert last value to int value.
        pad_value = ord(message[-1])
        # If the padded value is not 1-7, then no padding was added.
        if pad_value not in range(1,8):
            return message
        i = -2
        counter = 1
        # Loop to count the number of padding values.
        while message[i] == message[-1]:
            counter+=1;
            i-=1;
        # If the number of padding values equals the padding value then padding was used.
        if counter == pad_value:
            # Return the message without the padding.
            return message[0:-pad_value]
        else:
            return message
