import rsa


def generate_keys(length: int = 1024) -> tuple[str, str]:
    """
    :param int length: number of bits used to generate keys.
    :returns: a pair of string with public and private key in that order.
    """

    publicKeyRaw, privateKeyRaw = rsa.newkeys(nbits=length, accurate=True, poolsize=4)
    publicKeyStr = publicKeyRaw.save_pkcs1("PEM").decode("utf-8")
    privateKeyStr = privateKeyRaw.save_pkcs1("PEM").decode("utf-8")

    return publicKeyStr, privateKeyStr
