from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
import os

def encrypt_des_ecb(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, DES.block_size))

def encrypt_des_cbc(data, key):
    iv = os.urandom(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, DES.block_size))

def decrypt_des_ecb(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data), DES.block_size)

def decrypt_des_cbc(data, key):
    iv = data[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[DES.block_size:]), DES.block_size)


# read the file data
with open('/Users/mohabyasser/Desktop/Sample.txt', 'rb') as f:
    data = f.read()

# generate a random 8-byte key
key = os.urandom(8)
print("the key generated is ", key)

# encrypt the data using ECB mode of operation
encrypted_data_ecb = encrypt_des_ecb(data, key)

# encrypt the data using CBC mode of operation
encrypted_data_cbc = encrypt_des_cbc(data, key)

# write the encrypted data to new files
with open('/Users/mohabyasser/Desktop/Sample_encrypted_ecb.txt', 'wb') as f:
    f.write(encrypted_data_ecb)

with open('/Users/mohabyasser/Desktop/Sample_encrypted_cbc.txt', 'wb') as f:
    f.write(encrypted_data_cbc)
