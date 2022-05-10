import os
from enum import Enum
from typing import Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

""" TODO
    Uzgodnić format plików:
        - czy klucz symetryczny ma być na początku czy na końcu zaszyfrowanych danych
        - czy dodać do pliku informację o algorytmie symetrycznym
        - jeżeli tak to czy też tą informację trzeba zaszyfrować(asymetrycznie)
        - czy używać własnego formatu czy jakiegoś istniejącego np CMS(Cryptographic Message Syntax)
"""

class AsymmetricKey:
    def __init__(self, key: Union[RSAPrivateKey, RSAPublicKey]) -> None:
        self.key = key
        self.type = RSAPrivateKey if issubclass(type(self.key), RSAPrivateKey) else RSAPublicKey

    def toString(self, password: str = None) -> str:
        if self.type == RSAPrivateKey:
            encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password.encode('utf-8'))
            return self.key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=encryption).decode('utf-8')
        else:
            return self.key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    def __str__(self) -> str:
        return self.toString()

def generate_keys(length: int = 2048) -> tuple[AsymmetricKey, AsymmetricKey]:
    """
    :param int length: length of key in bits. 2048 and larger is considered secure. Should not be lower than 1024
    :returns: public and private keys.
    """

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=length)
    public_key = private_key.public_key()

    return AsymmetricKey(public_key), AsymmetricKey(private_key)

def saveKey(key: AsymmetricKey, name: str, password: str = None):
    """ Saves key in PEM format in private/ or public/ directory
    :param AsymmetricKey key: key to save
    :param str name: name of a key without extension. Saves as either public_{name}.key or private_{name}.key
    :param str password: used only for encrypting private key
    """
    os.makedirs('public', exist_ok=True)
    os.makedirs('private', exist_ok=True)
    filename = f'private/private_{name}.key' if key.type == RSAPrivateKey else f'public/public_{name}.key'
    with open(filename, 'w', encoding='utf-8') as file:
        print(key.toString(password), file=file)

def loadPrivateKeyFromFile(path: str, password: str = None) -> AsymmetricKey:
    """ load private key in PEM format
    :param str path: path to key
    :param str password: if key was encrypted then decrypt with password
    """
    with open(path, 'r', encoding='utf-8') as key_file:
        passwd = None if password is None else password.encode('utf-8')
        private = serialization.load_pem_private_key(key_file.read().encode('utf-8'), password=passwd)
        return AsymmetricKey(private)

def loadPublicKeyFromFile(path: str) ->AsymmetricKey:
    with open(path, 'r', encoding='utf-8') as key_file:
        public = serialization.load_pem_public_key(key_file.read().encode('utf-8'))
        return AsymmetricKey(public)

def _getDefaultPadding():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def _encryptAsymmetric(data: bytes, public_key: AsymmetricKey) -> bytes:
    """ encrypts data with public_key
        :param bytes data: data to encrypt, can't be longer than asymmetric key length(in bytes) - padding(66 bytes)
        :param AsymmetricKey public_key: key used to encrypt data
        :returns: encrypted data. It is the same length as asymmetric key(in bytes) e.g. 256 bytes if keys are 2048 bits long
    """
    encrypted_data = public_key.key.encrypt(data, _getDefaultPadding())
    return encrypted_data

def _decryptAsymmetric(encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
    decrypted_data = private_key.key.decrypt(encrypted_data, _getDefaultPadding())
    return decrypted_data

class SymmetricAlgorithm(Enum):
    DEFAULT = 0

def encrypt(data: bytes, public_key: AsymmetricKey, symmetric_encryption: SymmetricAlgorithm = SymmetricAlgorithm.DEFAULT) -> tuple[bytes, bytes]:
    """ generates symmetric key, encrypts data with this key, encrypts symmetric key with public_key
        :param bytes data: data to enrypt
        :param AsymmetricKey public_key: public key used to encrypt symmetric key
        :param SymmetricAlgorithm symmetric_encryption: algorithm used to encrypt data
        :returns: encrypted pair (encrypted_data, encrypted_symmetric_key)
    """
    encrypted_key: bytes = None
    encrypted_data: bytes = None
    if symmetric_encryption == SymmetricAlgorithm.DEFAULT:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        encrypted_key = _encryptAsymmetric(key, public_key)

    return (encrypted_data, encrypted_key)

def decrypt(encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
    """ decrypts encrypted_data using private_key
        :param bytes encrypted_data: bytes returned by encrypt() function(data + key)
        :param AsymmetricKey private_key: key that will be used to decrypt symmetric key
        :returns: decrypted data, without symmetric key
    """
    key_length: int = int(private_key.key.key_size / 8)
    encrypted_key = encrypted_data[-key_length:]
    encrypted_data_without_key = encrypted_data[:-key_length]

    key = _decryptAsymmetric(encrypted_key, private_key)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data_without_key)
    return decrypted_data