from Crypto.Cipher import AES
import random

def cbc_encrypt(plaintext, key, iv):
  cipher_text = bytearray()
  cipher = AES.new(key, AES.MODE_ECB)

  # read 128 bit blocks
  for i in range(0, len(plaintext), 16):
    block = plaintext[i:i+16]

    # add PKCS#7 padding
    if len(block) < 16:
        n_padding = 16 - len(block)
        block += bytes([n_padding] * n_padding)

    # XOR with IV
    block = bytes(a ^ b for a, b in zip(block, iv))
    cipher_block = cipher.encrypt(block)
    iv = cipher_block
    cipher_text.extend(cipher_block)

  return bytes(cipher_text)

def cbc_decrypt(ciphertext, key, iv):
  plaintext = bytearray()
  cipher = AES.new(key, AES.MODE_ECB)

  for i in range(0, len(ciphertext), 16):
    block = ciphertext[i:i+16]
    cipher_block = cipher.decrypt(block)

    # XOR with IV
    cipher_block = bytes(a ^ b for a, b in zip(cipher_block, iv))
    iv = block
    plaintext.extend(cipher_block)

  pad_len = plaintext[-1]
  if pad_len > 0 and pad_len <= 16:
      plaintext = plaintext[:-pad_len]

  return bytes(plaintext)

def submit(s,key,iv):
  s = s.replace(';','%3B')
  s = s.replace('=','%3D')

  msg = f'userid=456;userdata={s};session-id=31337'
  msg = msg.encode('ascii')
  return cbc_encrypt(msg,key,iv)

def verify(s,key,iv):

  msg = cbc_decrypt(s, key, iv).decode('ascii', errors='ignore')
  print(msg)

  if ';admin=true;' in msg:
    return True

  return False

if __name__ == '__main__':
    key = random.getrandbits(128).to_bytes(16, 'big')
    iv = random.getrandbits(128).to_bytes(16, 'big')
    ciphertext = cbc_encrypt('test'.encode('ascii'), key, iv)
    print(ciphertext.hex())

    secret = submit(';admin=true;', key, iv)
    print(verify(secret, key, iv))  # False

    # same length as ^
    secret = submit('abcdefghijk', key, iv)

    # xor mask
    xor = bytearray()
    flip = 'abcdefghijk'.encode('ascii')
    mask = ';admin=true'.encode('ascii')
    for a, b in zip(flip, mask):
        xor.append(a ^ b)
    xor = bytes(xor)

    # want to flip [21:31]
    catch = bytearray(secret)
    start_index = 4 # target bytes to flip are [5:15] (the preceding block)
    for i in range(len(xor)):
        catch[start_index + i] ^= xor[i]
    catch = bytes(catch)

    print(verify(catch, key, iv))  # should be true