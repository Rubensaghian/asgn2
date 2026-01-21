from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
BMP_HEADER_SIZE = 54

def pkcs7_pad(data: bytes) -> bytes:
    padLen = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padLen] * padLen)

def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i : (i + BLOCK_SIZE)]
        ciphertext += cipher.encrypt(block)

    return ciphertext

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i : (i + BLOCK_SIZE)]
        block = xor_bytes(block, prev)
        encryptedBlock = cipher.encrypt(block)
        ciphertext += encryptedBlock
        prev = encryptedBlock

    return ciphertext

def encrypt_bmp_ecb(input_file: str, output_file: str):
    with open(input_file, "rb") as f:
        bmp = f.read()

    header = bmp[:BMP_HEADER_SIZE]
    body = bmp[BMP_HEADER_SIZE:]

    key = get_random_bytes(BLOCK_SIZE)
    paddedBody = pkcs7_pad(body)

    encryptedBody = ecb_encrypt(paddedBody, key)

    with open(output_file, "wb") as f:
        f.write(header + encryptedBody)

def encrypt_bmp_cbc(input_file: str, output_file: str):
    with open(input_file, "rb") as f:
        bmp = f.read()

    header = bmp[:BMP_HEADER_SIZE]
    body = bmp[BMP_HEADER_SIZE:]

    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)
    paddedBody = pkcs7_pad(body)

    encryptedBody = cbc_encrypt(paddedBody, key, iv)

    with open(output_file, "wb") as f:
        f.write(header + encryptedBody)

if __name__ == "__main__":
    encrypt_bmp_ecb("./cp-logo.bmp", "cp-logo-ecb.bmp")
    encrypt_bmp_cbc("./cp-logo.bmp", "cp-logo-cbc.bmp")
    encrypt_bmp_ecb("./mustang.bmp", "mustang-ecb.bmp")
    encrypt_bmp_cbc("./mustang.bmp", "mustang-cbc.bmp")