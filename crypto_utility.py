from crypto_classes import *
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def getDefaultPadding():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def encryptAsymmetric(data: bytes, public_key: AsymmetricKey) -> bytes:
    """ encrypts data with public_key
        :param bytes data: data to encrypt, can't be longer than asymmetric key length(in bytes) - padding(66 bytes)
        :param AsymmetricKey public_key: key used to encrypt data
        :returns: encrypted data. It is the same length as asymmetric key(in bytes) e.g. 256 bytes if keys are 2048 bits long
    """
    encrypted_data = public_key.key.encrypt(data, getDefaultPadding())
    return encrypted_data


def decryptAsymmetric(encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
    decrypted_data = private_key.key.decrypt(encrypted_data, getDefaultPadding())
    return decrypted_data


def generateKeyFromSharedSecret(symmetric_encryption: SymmetricAlgorithm, symmetric_key_length: int = None, shared_key: bytes = None) -> tuple[bytes, bytes]:
    length = 32
    if symmetric_encryption.value > SymmetricAlgorithm.ChaCha20_Poly1305.value:
        length = int(symmetric_key_length / 8)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b'derived_key').derive(shared_key)
    nonce = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'nonce').derive(shared_key)
    if symmetric_encryption == SymmetricAlgorithm.LIB_DEFAULT:
        derived_key = base64.urlsafe_b64encode(derived_key)
        nonce = None
    return derived_key, nonce


def generateSymmetricKey(symmetric_encryption: SymmetricAlgorithm, symmetric_key_length: int = None, shared_key: bytes = None) -> tuple[bytes, bytes]:
    if symmetric_encryption == SymmetricAlgorithm.NONE:
        if shared_key is None:
            return (None, None)
        else:
            raise ValueError("ECC needs symmetric algorithm!")
    if shared_key is not None:
        return generateKeyFromSharedSecret(symmetric_encryption, symmetric_key_length, shared_key)
    else:
        nonce = os.urandom(16)
        if symmetric_encryption == SymmetricAlgorithm.LIB_DEFAULT:
            return (Fernet.generate_key(), None)
        elif symmetric_encryption == SymmetricAlgorithm.ChaCha20_Poly1305:
            return (ChaCha20Poly1305.generate_key(), nonce)
        elif symmetric_encryption.value > SymmetricAlgorithm.ChaCha20_Poly1305.value and symmetric_encryption.value <= SymmetricAlgorithm.AES_SIV.value:
            cipher = ENUM_TO_CLASS[symmetric_encryption]
            return (cipher.generate_key(symmetric_key_length), nonce)
        elif symmetric_encryption == SymmetricAlgorithm.AES_CBC:
            return (os.urandom(int(symmetric_key_length / 8)), nonce)
