from enum import Enum
import random
import string

class AssymetricKeyType(Enum):
    RSA = 1
    TEMPORARY = 2

class AssymetricKey:
    def __init__(self, key, key_type) -> None:
        self.key = key
        self.key_type = key_type

def generateKeys(type: AssymetricKeyType, length_bytes: int) -> tuple[AssymetricKey, AssymetricKey]:
    """ generates pair of assymetric keys: (private, public)
    """
    chars = string.digits + string.ascii_letters + string.punctuation
    private = ''.join(random.SystemRandom().choices(chars, k=length_bytes))
    public = ''.join(random.SystemRandom().choices(chars, k=length_bytes))
    return (AssymetricKey(private, type), AssymetricKey(public, type))

