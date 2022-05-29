import base64
from enum import Enum
from typing import Final, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, AESSIV, ChaCha20Poly1305


class SymmetricAlgorithm(Enum):
    NONE = 0
    # AUTHENTICATED
    LIB_DEFAULT = 1
    ChaCha20_Poly1305 = 2
    AES_GCM = 3
    AES_CCM = 4
    AES_SIV = 5
    # NOT AUTHENTICATED
    AES_CBC = 6

class AsymmetricAlgorithm(Enum):
    RSA = 0
    ECC_SECP256K1 = 1


""" Possible key lengths for symmetric algorithms """
KEY_LENGTHS: Final[dict[Union[SymmetricAlgorithm, AsymmetricAlgorithm], list[int]]] = {
    AsymmetricAlgorithm.RSA : [1024, 2048, 4096, 8192],
    AsymmetricAlgorithm.ECC_SECP256K1 : [],
    SymmetricAlgorithm.NONE : [],
    SymmetricAlgorithm.LIB_DEFAULT : [256],
    SymmetricAlgorithm.ChaCha20_Poly1305 : [256],
    SymmetricAlgorithm.AES_GCM : [128, 192, 256],
    SymmetricAlgorithm.AES_CCM : [128, 192, 256],
    SymmetricAlgorithm.AES_SIV : [256, 384, 512],
    SymmetricAlgorithm.AES_CBC : [128, 192, 256],
}

ENUM_TO_CLASS: dict[Union[AESGCM, AESCCM, AESSIV, ChaCha20Poly1305]] = {
    SymmetricAlgorithm.AES_GCM : AESGCM,
    SymmetricAlgorithm.AES_CCM : AESCCM,
    SymmetricAlgorithm.AES_SIV : AESSIV,
    SymmetricAlgorithm.ChaCha20_Poly1305 : ChaCha20Poly1305}

class AsymmetricKey:
    def __init__(self, key: Union[RSAPrivateKey, RSAPublicKey, EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> None:
        self.key = key

    def toBytes(self, *, password: str = None) -> bytes:
        if self.getType() == RSAPrivateKey or self.getType() == EllipticCurvePrivateKey:
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

    def getType(self) -> Union[RSAPrivateKey, RSAPublicKey, EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        if issubclass(type(self.key), RSAPrivateKey):
            return RSAPrivateKey
        elif issubclass(type(self.key), RSAPublicKey):
            return RSAPublicKey
        elif issubclass(type(self.key), EllipticCurvePrivateKey):
            return EllipticCurvePrivateKey
        elif issubclass(type(self.key), EllipticCurvePublicKey):
            return EllipticCurvePublicKey
        else:
            raise ValueError("Unknown key type!")


class EncryptedFile:
    def __init__(self, *, encrypted_file: bytes=None, encrypted_data:bytes = None, asymmetric_alg: AsymmetricAlgorithm = None, symmetric_alg: SymmetricAlgorithm = None, symmetric_key_length: int = None, e_key: bytes = None, encrypted_nonce: bytes = None) -> None:
        """ Metadata + encrypted data.

            Constructors:
            EncryptedFile(encrypted_file)
            EncryptedFile(encrypted_data, asymmetric_alg, symmetric_alg[, symmetric_key_length, e_key[, encrypted_nonce]])
            
            e_key - either encrypted_symmetric_key or ECC_public_key(if asymmetric_alg is ECC_*)

            File looks like this:
            encrypted_file = (Metadata, encrypted_data)
            Metadata = (asymmetric_algorithm, symmetric_algorithm[, symmetric_key_length, e_key_length, e_key[, encrypted_nonce]])
            Metadata size in bytes = (1, 1, [2, 2, key_length[, key_length]]), 2 <= size <= 6 + 2*key_length
        """
        if(encrypted_file is not None):
            self.encrypted_file = encrypted_file
        else:
            encrypted_file_array = bytearray([asymmetric_alg.value, symmetric_alg.value])
            if symmetric_key_length is not None:
                encrypted_file_array += symmetric_key_length.to_bytes(2, 'little')
                encrypted_file_array += len(e_key).to_bytes(2, 'little')
                encrypted_file_array += e_key
                if encrypted_nonce is not None:
                    encrypted_file_array += encrypted_nonce
                
            encrypted_file_array += encrypted_data
            self.encrypted_file = bytes(encrypted_file_array)

        self._encrypted_nonce = None
        self.asymmetric_algorithm = AsymmetricAlgorithm(self.encrypted_file[0])
        self.symmetric_algorithm = SymmetricAlgorithm(self.encrypted_file[1])
        file_view = memoryview(self.encrypted_file)
        if self.symmetric_algorithm == SymmetricAlgorithm.NONE:
            self.symmetric_key_length = None
            self.e_key_length = None
            self._e_key = None
            self._encrypted_data = file_view[2:]
        else:
            self.symmetric_key_length = int.from_bytes(file_view[2:4], 'little')
            self.e_key_length = int.from_bytes(file_view[4:6], 'little')
            index = 6
            self._e_key = file_view[index : index + self.e_key_length]
            index += self.e_key_length
            if self.symmetric_algorithm != SymmetricAlgorithm.LIB_DEFAULT and self.asymmetric_algorithm != AsymmetricAlgorithm.ECC_SECP256K1:
                self._encrypted_nonce = file_view[index : index + self.e_key_length]
                index += self.e_key_length
            self._encrypted_data = file_view[index:]

    @property
    def e_key(self) -> bytes:
        return self._e_key.tobytes()
    @property
    def encrypted_data(self) -> bytes:
        return self._encrypted_data.tobytes()
    @property
    def encrypted_nonce(self) -> bytes:
        if self._encrypted_nonce is None:
            return bytes(0)
        return self._encrypted_nonce.tobytes()

    def getPrintableKey(self) -> bytes:
        """ encoded in base64 """
        return base64.b64encode(self.e_key)

    def getPrintableData(self) -> bytes:
        """ encoded in base64 if symmetric algorithm is NONE else no encoding
        """
        if self.symmetric_algorithm != SymmetricAlgorithm.LIB_DEFAULT:
            return base64.b64encode(self.encrypted_data)
        else:
            return self.encrypted_data

    def getPrintableMetadata(self) -> bytes:
        printable = base64.b64encode(bytes([self.asymmetric_algorithm.value,self.symmetric_algorithm.value]))
        if self.symmetric_key_length is not None:
            printable += base64.b64encode(self.symmetric_key_length.to_bytes(2,'little'))
            printable += base64.b64encode(self.e_key_length.to_bytes(2,'little'))
            printable += self.getPrintableKey()
            if self._encrypted_nonce is not None:
                printable += base64.b64encode(self.encrypted_nonce)
        return printable

    def getPrintableFile(self) -> bytes:
        return self.getPrintableMetadata() + self.getPrintableData()

    def __str__(self) -> str:
        return (f'Asymmetric algorithm: {self.asymmetric_algorithm.name}\n'
                f'Symmetric algorithm: {self.symmetric_algorithm.name}\n'
                f'Encrypted symmetric key length: {self.e_key_length}')
