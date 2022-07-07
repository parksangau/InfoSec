from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto import Random


def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


def aesDescrypt(encrypted, key, iv):
    cipher_Decrypted = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher_Decrypted.decrypt(encrypted)
    return plaintext


def aesEncryptedWithSHA512(message, key, iv):
    hash_Func = SHA512.new()
    hash_Func.update(message)
    hashOfMsg = hash_Func.digest()
    print("SHA512(message):", hashOfMsg.hex())
    return aesEncrypt(hashOfMsg + message, key, iv)    # Hash값 + message 붙여서 리턴


def aesDecryptWithSHA512(encryptedWithSHA512, key, iv):     # 전체를 먼저 복호화 후 잘라내기
    decryptedTemp = aesDescrypt(encryptedWithSHA512, key, iv)  # 64 -> SHA512.digest_size 와 같음
    decryptedSHA512 = decryptedTemp[:SHA512.digest_size]     # 앞에서부터 64 byte 자르기 (Hash 값)
    decryptedMsg = decryptedTemp[SHA512.digest_size:]       # 64 byte 뒷부분 자르기 (Message 값)
    return decryptedSHA512, decryptedMsg    # (line 64 참고) 각각의 값 return


def verifySHA512(decryptedSHA512, decryptedMsg):        # 두 값을 비교하는 func
    hash_Func = SHA512.new()
    hash_Func.update(decryptedMsg)
    if hash_Func.hexdigest() == decryptedSHA512.hex():
        return True     # 두 값이 같으면 True
    else:
        return False    # 두 값이 다르면 False


def main():
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!! Name : Park Sang-Eun!'
    print("Message:", message.decode())

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print("AES Key:", key.hex())
    print("IV:", iv.hex())

    #encrypted = aesEncrypt(message, key, iv)
    #print("Encrypted: ", encrypted.hex())

    encryptedWithSHA512 = aesEncryptedWithSHA512(message, key, iv)      # E[M||H(M)]
    print("Encrypted E(H(M)+M):", encryptedWithSHA512.hex())

    #decrypted = aeDescrypt(encrypted, key, iv)
    #print("Decrypted: ", decrypted.decode())
    #assert message == decrypted

    decryptedSHA512, decryptedMsg = aesDecryptWithSHA512(encryptedWithSHA512, key, iv)
    print("Decrypted SHA512:", decryptedSHA512.hex())
    print("Decrypted Message:", decryptedMsg)

    if (verifySHA512(decryptedSHA512, decryptedMsg)):
        print("Integrity OK, Correct Hash!!")
    else:
        print("Incorrect Hash!!")


if __name__ == "__main__":
    main()