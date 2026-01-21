from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def ecb_encrypt(path, key=None):
    # generate random key if not provided
    if key is None:
        key = get_random_bytes(16)  # 16 bytes = 128-bits

    # cipher setup and file object init
    cipher_text = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)
    f = open(path, 'rb')  # read binary mode

    # read 128-bit (16 byte) blocks
    while block := f.read(16):
        # add PKCS#7 padding if needed
        if len(block) < 16:
            n_padding = 16 - len(block)
            block += bytes([n_padding] * n_padding)
        cipher_block = cipher.encrypt(block)
        cipher_text.extend(cipher_block)
    f.close()
    f = open(path.split('.')[0] + "_encrypted", 'wb')
    f.write(cipher_text)
    f.close()
    return


# encrypt a file at a given path in ECB mode,
# using key (or randomly generated key if not provided)
def ecb_encrypt_bmp(path, key=None):
    # generate random key if not provided
    if key is None:
        key = get_random_bytes(16)  # 16 bytes = 128-bit AES key

    # cipher setup and file object init
    cipher_text = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)

    f = open(path, 'rb')  # read binary mode
    header = f.read(54)  # read the 54-byte BMP header

    # read 128-bit (16 byte) blocks
    while block := f.read(16):

        # add PKCS#7 padding if needed
        if len(block) < 16:
            n_padding = 16 - len(block)
            block += bytes([n_padding] * n_padding)

        cipher_block = cipher.encrypt(block)
        cipher_text.extend(cipher_block)

    f.close()
    f = open(path.split('.')[0] + "_ECB_encrypted.bmp", 'wb')
    f.write(header)  # write BMP header unchanged
    f.write(cipher_text)
    f.close()

    return


# encrypt a file at a given path in CBC mode,
# using key (or randomly generated key if not provided)
# and IV (or randomly generated IV if not provided)
def cbc_encrypt_bmp(path, key=None, iv=None):
    # generate random key and IV if not provided
    if key is None:
        key = get_random_bytes(16)  # 128-bits
    if iv is None:
        iv = get_random_bytes(16)  # 128-bits

    # cipher setup and file object init
    cipher_text = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)

    f = open(path, 'rb')  # read binary mode
    header = f.read(54)  # read the 54-byte BMP header

    # read 128-bit (16 byte) blocks
    while block := f.read(16):

        # add PKCS#7 padding if needed
        if len(block) < 16:
            n_padding = 16 - len(block)
            block += bytes([n_padding] * n_padding)

        # XOR with IV
        block = bytes(a ^ b for a, b in zip(block, iv))

        cipher_block = cipher.encrypt(block)
        iv = cipher_block  # update IV for next block
        cipher_text.extend(cipher_block)

    f.close()
    # write encrypted BMP
    f = open(path.split('.')[0] + "_CBC_encrypted.bmp", 'wb')
    f.write(header)  # write BMP header unchanged
    f.write(cipher_text)
    f.close()
    return


ecb_encrypt_bmp("cp-logo.bmp")
ecb_encrypt_bmp("mustang.bmp")
cbc_encrypt_bmp("cp-logo.bmp")
cbc_encrypt_bmp("mustang.bmp")
