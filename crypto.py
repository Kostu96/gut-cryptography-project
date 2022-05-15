import base64
import os
from enum import IntEnum
from typing import Final, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESSIV, AESCCM

""" TODO
    Uzgodnić format plików:
        - czy klucz symetryczny ma być na początku czy na końcu zaszyfrowanych danych
        - czy dodać do pliku informację o algorytmie symetrycznym
        - jeżeli tak to czy też tą informację trzeba zaszyfrować(asymetrycznie)
        - czy używać własnego formatu czy jakiegoś istniejącego np CMS(Cryptographic Message Syntax)
"""

class SymmetricAlgorithm(IntEnum):
    NONE = 0
    LIB_DEFAULT = 1
    ChaCha20_Poly1305 = 2
    AES_GCM = 3
    AES_CCM = 4
    AES_SIV = 5
    Camellia_CFB = 6

""" Possible key lengths for symmetric algorithms """
SYMMETRIC_KEY_LENGTHS: Final[dict[SymmetricAlgorithm, list[int]]] = {
    SymmetricAlgorithm.NONE : [],
    SymmetricAlgorithm.LIB_DEFAULT : [256],
    SymmetricAlgorithm.ChaCha20_Poly1305 : [256],
    SymmetricAlgorithm.AES_GCM : [128, 192, 256],
    SymmetricAlgorithm.AES_CCM : [128, 192, 256],
    SymmetricAlgorithm.AES_SIV : [256, 384, 512],
    SymmetricAlgorithm.Camellia_CFB : [128, 192, 256],
}

class AsymmetricAlgorithm(IntEnum):
    RSA = 0


class AsymmetricKey:
    def __init__(self, key: Union[RSAPrivateKey, RSAPublicKey]) -> None:
        self.key = key
        self.type = RSAPrivateKey if issubclass(type(self.key), RSAPrivateKey) else RSAPublicKey

    def toBytes(self, *, password: str = None) -> bytes:
        if self.type == RSAPrivateKey:
            encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password.encode('utf-8'))
            return self.key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=encryption)
        else:
            return self.key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def toString(self, *, password: str = None) -> str:
        return self.toBytes(password=password).decode('utf-8')

    def __str__(self) -> str:
        return self.toString()

    def getKeyLengthBits(self) -> int:
        return self.key.key_size
    
    def getKeyLengthBytes(self) -> int:
        return int(self.key.key_size / 8)


class EncryptedFile:
    def __init__(self, *, encrypted_file: bytes=None, encrypted_data:bytes = None, asymmetric_alg: AsymmetricAlgorithm = None, symmetric_alg: SymmetricAlgorithm = None, encrypted_key_length: int = 0, encrypted_nonce: bytes = None, encrypted_key: bytes = None) -> None:
        """ Metadata + encrypted data.

            EncryptedFile(encrypted_file)
            EncryptedFile(encrypted_data, asymmetric_alg, symmetric_alg[, encrypted_key_length[, encrypted_nonce], encrypted_key])

            File looks like this:
            encrypted_file = (Metadata, encrypted_data)
            Metadata = (asymmetric_algorithm, symmetric_algorithm[, key_length[, encrypted_nonce], encrypted_symmetric_key])
            Metadata size in bytes = (1, 1, [2[, key_length], key_length]), 2 <= size <= 4 + 2*key_length
        """
        if(encrypted_file is not None):
            self.encrypted_file = encrypted_file
        else:
            encrypted_file_array = bytearray([asymmetric_alg, symmetric_alg])
            if encrypted_key is not None:
                encrypted_file_array += encrypted_key_length.to_bytes(2, 'little')
                if encrypted_nonce is not None:
                    encrypted_file_array += encrypted_nonce
                encrypted_file_array += encrypted_key
            encrypted_file_array += encrypted_data
            self.encrypted_file = bytes(encrypted_file_array)
        self._encrypted_nonce = None
        self.asymmetric_algorithm = AsymmetricAlgorithm(self.encrypted_file[0])
        self.symmetric_algorithm = SymmetricAlgorithm(self.encrypted_file[1])
        file_view = memoryview(self.encrypted_file)
        if self.symmetric_algorithm == SymmetricAlgorithm.NONE:
            self.encrypted_key_length = None
            self._encrypted_key = None
            self._encrypted_data = file_view[2:]
        else:
            self.encrypted_key_length = int.from_bytes(file_view[2:4], 'little')
            key_start = 4
            if self.symmetric_algorithm != SymmetricAlgorithm.LIB_DEFAULT:
                self._encrypted_nonce = file_view[4 : 4 + self.encrypted_key_length]
                key_start += self.encrypted_key_length
            self._encrypted_key = file_view[key_start : key_start + self.encrypted_key_length]
            self._encrypted_data = file_view[key_start + self.encrypted_key_length :]

    @property
    def encrypted_key(self) -> bytes:
        return self._encrypted_key.tobytes()
    @property
    def encrypted_data(self) -> bytes:
        return self._encrypted_data.tobytes()
    @property
    def encrypted_nonce(self) -> bytes:
        return self._encrypted_nonce.tobytes()

    def getPrintableKey(self) -> bytes:
        """ encoded in base64 """
        return base64.b64encode(self.encrypted_key)

    def getPrintableData(self) -> bytes:
        """ encoded in base64 if symmetric algorithm is NONE else no encoding
        """
        if self.symmetric_algorithm != SymmetricAlgorithm.LIB_DEFAULT:
            return base64.b64encode(self.encrypted_data)
        else:
            return self.encrypted_data

    def __str__(self) -> str:
        return (f'Asymmetric algorithm: {self.asymmetric_algorithm.name}\n'
                f'Symmetric algorithm: {self.symmetric_algorithm.name}\n'
                f'Encrypted symmetric key length: {self.encrypted_key_length}')


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
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)

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

def decryptAsymmetric(a,b) -> bytes:
    return _decryptAsymmetric(a,b)

__ENUM_TO_CLASS: dict[Union[AESGCM, AESCCM, AESSIV, ChaCha20Poly1305]] = {SymmetricAlgorithm.AES_GCM : AESGCM,
                    SymmetricAlgorithm.AES_CCM : AESCCM,
                    SymmetricAlgorithm.AES_SIV : AESSIV,
                    SymmetricAlgorithm.ChaCha20_Poly1305 : ChaCha20Poly1305}

def encrypt(data: bytes, public_key: AsymmetricKey, symmetric_encryption: SymmetricAlgorithm = SymmetricAlgorithm.LIB_DEFAULT, symmetric_key_length: int = None) -> EncryptedFile:
    """ generates symmetric key, encrypts data with this key, encrypts symmetric key with public_key
        :param bytes data: data to enrypt
        :param AsymmetricKey public_key: public key used to encrypt symmetric key
        :param SymmetricAlgorithm symmetric_encryption: algorithm used to encrypt data
        :param int symmetric_key_length: symmetric key length, only used if symmetric_encryption.value > 2
        :returns: encrypted pair (encrypted_data, encrypted_symmetric_key)
    """
    if symmetric_encryption.value > 2 and symmetric_key_length not in SYMMETRIC_KEY_LENGTHS[symmetric_encryption]:
        raise ValueError("Wrong symmetric key length!")
    key = None
    nonce = None
    encrypted_key: bytes = None
    encrypted_nonce: bytes = None
    encrypted_data: bytes = None
    if symmetric_encryption == SymmetricAlgorithm.NONE:
        encrypted_data = _encryptAsymmetric(data, public_key)
    elif symmetric_encryption == SymmetricAlgorithm.LIB_DEFAULT:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
    elif symmetric_encryption >= SymmetricAlgorithm.ChaCha20_Poly1305 and symmetric_encryption < SymmetricAlgorithm.AES_SIV:
        cipher = __ENUM_TO_CLASS[symmetric_encryption]
        key = cipher.generate_key(symmetric_key_length) if symmetric_encryption != SymmetricAlgorithm.ChaCha20_Poly1305 else cipher.generate_key()
        encryptor = cipher(key)
        nonce = os.urandom(12)
        encrypted_data = encryptor.encrypt(nonce, data, None)
    elif symmetric_encryption == SymmetricAlgorithm.AES_SIV:
        key = AESSIV.generate_key(symmetric_key_length)
        aessiv = AESSIV(key)
        nonce = os.urandom(16)
        encrypted_data = aessiv.encrypt(data, [nonce])
    elif symmetric_encryption == SymmetricAlgorithm.Camellia_CFB:
        key = os.urandom(int(symmetric_key_length / 8))
        nonce = os.urandom(16) # actually initialization vector
        cipher = Cipher(algorithm=algorithms.Camellia(key),
                        mode=modes.CFB(nonce))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

    if key is not None:
        encrypted_key = _encryptAsymmetric(key, public_key)
    if nonce is not None:
        encrypted_nonce = _encryptAsymmetric(nonce, public_key)

    return EncryptedFile(encrypted_data=encrypted_data,
                        asymmetric_alg=AsymmetricAlgorithm.RSA,
                        symmetric_alg=symmetric_encryption,
                        encrypted_key_length=int(public_key.key.key_size / 8),
                        encrypted_nonce=encrypted_nonce, encrypted_key=encrypted_key)

def decrypt(encrypted_file: bytes, private_key: AsymmetricKey) -> bytes:
    """ decrypts encrypted_data using private_key
        :param bytes encrypted_data: bytes returned by encrypt() function(data + key)
        :param AsymmetricKey private_key: key that will be used to decrypt symmetric key
        :returns: decrypted data, without symmetric key
    """
    encrypted = EncryptedFile(encrypted_file=encrypted_file)
    decrypted_data: bytes = None
    key = None
    nonce = None
    if encrypted.symmetric_algorithm != SymmetricAlgorithm.NONE:
        key = _decryptAsymmetric(encrypted.encrypted_key, private_key)
    if encrypted.symmetric_algorithm >= SymmetricAlgorithm.ChaCha20_Poly1305:
        nonce = _decryptAsymmetric(encrypted.encrypted_nonce, private_key)

    if encrypted.symmetric_algorithm == SymmetricAlgorithm.NONE:
        decrypted_data = _decryptAsymmetric(encrypted.encrypted_data, private_key)
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.LIB_DEFAULT:
        decrypted_data = Fernet(key).decrypt(encrypted.encrypted_data)
    elif encrypted.symmetric_algorithm >= SymmetricAlgorithm.ChaCha20_Poly1305 and encrypted.symmetric_algorithm < SymmetricAlgorithm.AES_SIV:
        cipher = __ENUM_TO_CLASS[encrypted.symmetric_algorithm]
        decrypted_data = cipher(key).decrypt(nonce, encrypted.encrypted_data, None)
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.AES_SIV:
        decrypted_data = AESSIV(key).decrypt(encrypted.encrypted_data, [nonce])
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.Camellia_CFB:
        decryptor = Cipher(algorithm=algorithms.Camellia(key), mode= modes.CFB(nonce)).decryptor()
        decrypted_data = decryptor.update(encrypted.encrypted_data) + decryptor.finalize()

    return decrypted_data