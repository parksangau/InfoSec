from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto import Random
from RSA_Test import rsaEncrypt, rsaDecrypt


def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')
    print("%s's private Key: %s " % (userName, priKey)) # ,(콤마) 대신 %(퍼센트) 활용해서 각 파라미터 불러오기
    pubKey = privateKey.publickey()
    print("%s's public Key: %s" % (userName, pubKey.exportKey('PEM')))
    return priKey, pubKey


# pubKey 이용해 encrypt 하는 func
def rsaEncrypt(message, pubKey):
    rsaCipher = PKCS1_OAEP.new(pubKey)
    ciphertext = rsaCipher.encrypt(message)
    return ciphertext


def rsaDecrypt(encrypted, priKey):
    privateKey = RSA.importKey(priKey)   # priKey 를 RSA 형태로 다시 읽어들이기
    rsaCipher = PKCS1_OAEP.new(privateKey)
    plaintext = rsaCipher.decrypt(encrypted)
    return plaintext


def rsaDigSignGen(message, priKey): # 서명을 생성하고자 하는 사람의 priKey
    # hashMsgObj = SHA512.new()
    # hashMsgObj.update(message) # 두줄과 아래 한줄이 같은 의미임
    hashMsgObj = SHA512.new(message)
    privateKey = RSA.importKey(priKey)  # privateKey 를 받아와야함
    signGenObj = PKCS1_v1_5.new(privateKey)
    signMsg = signGenObj.sign(hashMsgObj)
    return signMsg


def rsaDigSignVerify(signMsg, message, pubKey):
    hashMsgObj = SHA512.new(message)
    signVerifyObj = PKCS1_v1_5.new(pubKey)
    if signVerifyObj.verify(hashMsgObj, signMsg):
        return True
    else:
        return False

def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext

def aesDescrypt(encrypted, key, iv):
    cipher_Decrypted = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher_Decrypted.decrypt(encrypted)
    return plaintext

def main():
    message = b'Information security and Programming, Test Message!!! Name : Park Sang-Eun!!!'
    print("Message : ", message.decode())
    BLOCK_SIZE = 16
    KEY_SIZE = 32

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print("AES Key: ", key.hex())
    print("IV: ", iv.hex())

    print("\n**RSA Key Pairs(priKey, pubKey) Generation")
    # alice & bob RSA key pairs Generation
    alice_private, alice_pubKey = gen_RSA_Key('Alice')
    bob_priKey, bob_pubKey = gen_RSA_Key('Bob')

    # alice : message --> digital signature generation & AES encryption
    signMsg = rsaDigSignGen(message, alice_private)
    print("Length of Signature: ", len(signMsg))

    encrypted = aesEncrypt(signMsg+message, key, iv)
    print("AES Encryption E(Sign(H(M))+M): ", encrypted.hex())
    print("Length of Encrypted(Sign(H(M))+M): ", len(encrypted))
    print("Sending: ", encrypted.hex())
    print("**** Alice : Sending Encrypted Message...\n")

    # bob : message ---> received & AES decryption
    print("\n**** Bob : Receiving Encrypted Message...")
    print("Received: ", encrypted.hex())

    decryptedReceived = aesDescrypt(encrypted, key, iv)
    print("AES Descryption D(E(Sign(H(M))+M)): ", decryptedReceived.hex())

    decryptedSign = decryptedReceived[:256]
    print("Decrypted Sign: ", decryptedSign.hex())

    decryptedMsg = decryptedReceived[256:]
    print("Decrypted Message: ", decryptedMsg.decode())

    # 전달받은 서명 값과 해시 값 확인
    if rsaDigSignVerify(decryptedSign, decryptedMsg, alice_pubKey):
        print("Digital Signature Verification on Decryption Message: Correct. Verification OK!!!")
    else:
        print("Digital Signature Verification Fail!!!")

if __name__ == "__main__":
    main()