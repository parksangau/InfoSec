from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP # open 형태의 encrypt 프로토콜(=RSA)
from Crypto.Signature import PKCS1_v1_5


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


def main():
    message = b'This is Test Message!!! Im Park Sang-Eun'
    print("Message : ", message.decode())

    # alice & bob RSA key pairs Generation
    alice_private, alice_pubKey = gen_RSA_Key('alice')
    bob_priKey, bob_pubKey = gen_RSA_Key('bob')

    # alice --> bob : messagge encrypt ---> sending...
    # alice : using "bob's publicKey" -> message encrypt


    encrypted = rsaEncrypt(message, bob_pubKey)
    print("RSA_Encrypt(message, bob_pubKey): ", encrypted.hex()) #E_bob's_pubKey
    # alice : message --> digital signature generation
    signMsg = rsaDigSignGen(message, alice_private)
    print("Digital Signature on input Message: ", signMsg.hex())
    print("Size of Digital Signature: ", len(signMsg))

    """
    Client-Server Network(TCP/IP) Data Sending : "encrypted" data + "signMSG (digital signature)" data
    """

    # Network : from alice (encrypted ---> sending) to bob
    # bob : decrypt ... using bob's privateKey...
    decrypted = rsaDecrypt(encrypted, bob_priKey)
    print("RSA_Decrypt(ciphertext, bob_priKey): ", decrypted.decode())

    # 전달받은 서명 값과 해시 값 확인
    if rsaDigSignVerify(signMsg, decrypted, alice_pubKey):
        print("Digital Signature Verification on Decryption Message: Correct. Verification OK!!!")
    else:
        print("Digital Signature Verification Fail!!!")


if __name__ == "__main__":
    main()