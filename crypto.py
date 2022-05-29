from crypto_classes import *
from crypto_utility import *
import os
from typing import Literal
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV


def generate_keys(type: AsymmetricAlgorithm = AsymmetricAlgorithm.RSA, length: int = 2048) -> tuple[AsymmetricKey, AsymmetricKey]:
    """
    :param AsymmetricAlgorithm type: Either RSA or ECC(Elliptic-Curve Cryptography)
    :param int length: Only used for RSA. length of key in bits. 2048 and larger is considered secure. Should not be lower than 1024
    :returns: public and private keys.
    """
    private_key = None
    public_key = None

    if type == AsymmetricAlgorithm.RSA:
        if length not in KEY_LENGTHS[AsymmetricAlgorithm.RSA]:
            raise ValueError("Wrong key length!")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length)
        public_key = private_key.public_key()

    if type == AsymmetricAlgorithm.ECC_SECP256K1:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

    if private_key is None or public_key is None:
        raise ValueError("None private/public key!")

    return AsymmetricKey(public_key), AsymmetricKey(private_key)


def saveKey(key: AsymmetricKey, name: str, password: str = None):
    """ Saves key in PEM format in private/ or public/ directory
    :param AsymmetricKey key: key to save
    :param str name: name of a key without extension. Saves as either public_{name}.key or private_{name}.key
    :param str password: used only for encrypting private key
    """
    os.makedirs('public', exist_ok=True)
    os.makedirs('private', exist_ok=True)
    path = ''
    if key.getType() == RSAPrivateKey or key.getType() == EllipticCurvePrivateKey:
        path = f'private/private_{name}.key'
    else:
        path = f'public/public_{name}.key'
    with open(path, 'w', encoding='utf-8') as file:
        print(key.toString(password=password), file=file)


def loadKeyFromStr(key: str, type: Literal['public', 'private'], password: str = None) -> AsymmetricKey:
    return loadKeyFromBytes(key.encode('utf-8'), type, password)


def loadKeyFromBytes(key: str, type: Literal['public', 'private'], password: str = None) -> AsymmetricKey:
    if type == 'public':
        return AsymmetricKey(serialization.load_pem_public_key(key))
    elif type == 'private':
        passwd = None if password is None else password.encode('utf-8')
        return AsymmetricKey(serialization.load_pem_private_key(key, password=passwd))


def loadPrivateKeyFromFile(path: str, password: str = None) -> AsymmetricKey:
    """ load private key in PEM format
    :param str path: path to key
    :param str password: if key was encrypted then decrypt with password
    """
    with open(path, 'r', encoding='utf-8') as key_file:
        return loadKeyFromStr(key_file.read(), 'private', password)


def loadPublicKeyFromFile(path: str) -> AsymmetricKey:
    with open(path, 'r', encoding='utf-8') as key_file:
        return loadKeyFromStr(key_file.read(), 'public')


def encrypt(data: bytes, public_key: AsymmetricKey, symmetric_encryption: SymmetricAlgorithm = SymmetricAlgorithm.LIB_DEFAULT, symmetric_key_length: int = None) -> EncryptedFile:
    """ generates symmetric key, encrypts data with this key, encrypts symmetric key with public_key
        :param bytes data: data to enrypt
        :param AsymmetricKey public_key: public key used to encrypt symmetric key
        :param SymmetricAlgorithm symmetric_encryption: algorithm used to encrypt data
        :param int symmetric_key_length: symmetric key length, only used if symmetric_encryption.value > 2
        :returns: encrypted pair (encrypted_data, encrypted_symmetric_key)
    """
    if symmetric_encryption.value > 2 and symmetric_key_length not in KEY_LENGTHS[symmetric_encryption]:
        raise ValueError("Wrong symmetric key length!")
    if symmetric_key_length is None and symmetric_encryption != SymmetricAlgorithm.NONE:
        symmetric_key_length = KEY_LENGTHS[symmetric_encryption][0]
    shared_key = None
    public_ECC = None
    if public_key.getType() == EllipticCurvePublicKey:
        public_ECC, private_ECC = generate_keys(AsymmetricAlgorithm.ECC_SECP256K1)
        shared_key = private_ECC.key.exchange(ec.ECDH(), public_key.key)
    key, nonce = generateSymmetricKey(symmetric_encryption, symmetric_key_length, shared_key)
    e_key: bytes = None
    encrypted_nonce: bytes = None
    encrypted_data: bytes = None
    if symmetric_encryption == SymmetricAlgorithm.NONE:
        encrypted_data = encryptAsymmetric(data, public_key)
    elif symmetric_encryption == SymmetricAlgorithm.LIB_DEFAULT:
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
    elif SymmetricAlgorithm.ChaCha20_Poly1305.value <= symmetric_encryption.value < SymmetricAlgorithm.AES_SIV.value:
        cipher = ENUM_TO_CLASS[symmetric_encryption]
        encryptor = cipher(key)
        encrypted_data = encryptor.encrypt(nonce[:12], data, None)
    elif symmetric_encryption == SymmetricAlgorithm.AES_SIV:
        aessiv = AESSIV(key)
        encrypted_data = aessiv.encrypt(data, [nonce])
    elif symmetric_encryption == SymmetricAlgorithm.AES_CBC:
        cipher = Cipher(algorithm=algorithms.AES(key),
                        mode=modes.CBC(nonce))
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()

    asym_alg_type = AsymmetricAlgorithm.RSA

    if public_key.getType() != EllipticCurvePublicKey:
        if key is not None:
            e_key = encryptAsymmetric(key, public_key)
        if nonce is not None:
            encrypted_nonce = encryptAsymmetric(nonce, public_key)
    else:
        e_key = public_ECC.toBytes()
        asym_alg_type = AsymmetricAlgorithm.ECC_SECP256K1

    return EncryptedFile(encrypted_data=encrypted_data,
                         asymmetric_alg=asym_alg_type,
                         symmetric_alg=symmetric_encryption,
                         symmetric_key_length=symmetric_key_length,
                         e_key=e_key,
                         encrypted_nonce=encrypted_nonce)


def decrypt(encrypted_file: bytes, private_key: AsymmetricKey) -> bytes:
    """ decrypts encrypted_file using private_key
        :param bytes encrypted_file: EncryptedFile.encrypted_file returned by encrypt
        :param AsymmetricKey private_key: key that will be used to decrypt symmetric key
        :returns: decrypted data without metadata
    """
    encrypted = EncryptedFile(encrypted_file=encrypted_file)
    decrypted_data: bytes = None
    key = None
    nonce = None
    if encrypted.asymmetric_algorithm == AsymmetricAlgorithm.ECC_SECP256K1:
        public_ECC = loadKeyFromBytes(encrypted.e_key, 'public')
        shared_secret = private_key.key.exchange(ec.ECDH(), public_ECC.key)
        key, nonce = generateKeyFromSharedSecret(encrypted.symmetric_algorithm, encrypted.symmetric_key_length, shared_secret)
    else:
        if encrypted.symmetric_algorithm != SymmetricAlgorithm.NONE:
            key = decryptAsymmetric(encrypted.e_key, private_key)
        if encrypted.symmetric_algorithm.value >= SymmetricAlgorithm.ChaCha20_Poly1305.value:
            nonce = decryptAsymmetric(encrypted.encrypted_nonce, private_key)

    if encrypted.symmetric_algorithm == SymmetricAlgorithm.NONE:
        decrypted_data = decryptAsymmetric(encrypted.encrypted_data, private_key)
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.LIB_DEFAULT:
        decrypted_data = Fernet(key).decrypt(encrypted.encrypted_data)
    elif SymmetricAlgorithm.ChaCha20_Poly1305.value <= encrypted.symmetric_algorithm.value < SymmetricAlgorithm.AES_SIV.value:
        cipher = ENUM_TO_CLASS[encrypted.symmetric_algorithm]
        decrypted_data = cipher(key).decrypt(nonce[:12], encrypted.encrypted_data, None)
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.AES_SIV:
        decrypted_data = AESSIV(key).decrypt(encrypted.encrypted_data, [nonce])
    elif encrypted.symmetric_algorithm == SymmetricAlgorithm.AES_CBC:
        decryptor = Cipher(algorithm=algorithms.AES(key), mode= modes.CBC(nonce)).decryptor()
        decrypted_data = decryptor.update(encrypted.encrypted_data) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data
