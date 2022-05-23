import io
import math
import time
from matplotlib import pyplot as plt
import crypto
from crypto_classes import AsymmetricAlgorithm, SymmetricAlgorithm, AsymmetricKey

Pixel = tuple[int, int, int]
Row = list[Pixel]
Image = list[Row]

def bytesToImage(bytes_arr: bytes, row_size: int = None) -> Image:
    if row_size is None:
        row_size = int(math.sqrt(len(bytes_arr) / 3))
    vector_stream = io.BytesIO(bytes_arr)
    image: Image = []
    while True:
        row: Row = []
        for _ in range(row_size):
            colors = vector_stream.read(3)
            if len(colors) < 3:
                break
            row.append(tuple(colors))
        if len(row) == 0:
            break
        else:
            # padding too short row
            row += [(0,0,0) for _ in range(row_size - len(row))]
            image.append(row)

    return image

def imageToBytes(image: Image) -> bytes:
    serialized: bytearray = bytearray()
    for row in image:
        for pixel in row:
            for color in pixel:
                serialized.append(color.to_bytes(1, 'little')[0])
    return bytes(serialized)

def showTestImage(image: list[Row], public_key: AsymmetricKey, private_key: AsymmetricKey, symmetric_alg: SymmetricAlgorithm, key_length: int = None, columns: int = 3):
    image_bytes = imageToBytes(image)
    print(f'Image size = {len(image_bytes)}, algorithm = {symmetric_alg.name}({key_length})')
    start = time.perf_counter()
    encrypted_file = crypto.encrypt(image_bytes, public_key, symmetric_alg, key_length)
    elapsed = time.perf_counter() - start
    print(f'encryption time = {elapsed} ms')

    encrypted_image = bytesToImage(encrypted_file.encrypted_data)
    start = time.perf_counter()
    decrypted_image_bytes = crypto.decrypt(encrypted_file.encrypted_file, private_key) 
    elapsed = time.perf_counter() - start
    print(f'decryption time = {elapsed} ms')
    decrypted_image = bytesToImage(decrypted_image_bytes)

    plt.figure(figsize=(16,4))
    plt.suptitle(f"Szyfrowanie RSA-4096-{symmetric_alg.name}")
    plt.subplot(1,columns,1)
    plt.imshow(image, interpolation='nearest')
    plt.title("Oryginalny obraz")
    plt.subplot(1,columns,2)
    plt.imshow(encrypted_image, interpolation='nearest')
    plt.title("Zaszyfrowany obraz")
    plt.subplot(1,columns,3)
    plt.imshow(decrypted_image, interpolation='nearest')
    plt.title("Odszyfrowany obraz")


def main():
    image_to_test = [[(255, 0, 0) for _ in range(12)] for _ in range(12)]
    image_to_test[2][2] = (0,0,255)
    public_key, private_key = crypto.generate_keys(crypto.AsymmetricAlgorithm.RSA, 4096)

    showTestImage(image_to_test, public_key, private_key, SymmetricAlgorithm.NONE)

    image_to_test = [[(255, 0, 0) for _ in range(25)] for _ in range(25)]
    image_to_test[2][2] = (0,0,255)

    showTestImage(image_to_test, public_key, private_key, SymmetricAlgorithm.AES_CBC, 128, 4)
    image_bytes = imageToBytes(image_to_test)
    encrypted_file = crypto.encrypt(image_bytes, public_key, crypto.SymmetricAlgorithm.AES_CBC, 128)
    # flip least significant bit of last 100th byte
    corrupted_file = encrypted_file.encrypted_file[:-100] + (encrypted_file.encrypted_file[-100] ^ 1).to_bytes(1, 'little') + encrypted_file.encrypted_file[-99:]
    corrupted_image = bytesToImage(crypto.decrypt(corrupted_file, private_key))
    plt.subplot(1,4,4)
    plt.imshow(corrupted_image, interpolation='nearest')
    plt.title("Odszyfrowany obraz z przekłamanym bitem")

    image_to_test = [[(255, 0, 0) for _ in range(1000)] for _ in range(1000)]
    image_to_test[2][2] = (0,0,255)
    showTestImage(image_to_test, public_key, private_key, SymmetricAlgorithm.AES_GCM, 256)
    plt.show()

if __name__ == "__main__":
    main()