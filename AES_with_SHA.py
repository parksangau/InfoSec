from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto import Random

def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext

def aesDescrypt(encrypyed, key, iv):
    cipher_Descrypted = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher_Descrypted.decrypt(encrypyed)
    return plaintext


