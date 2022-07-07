from Crypto.Hash import SHA512

# hash 값 생성 과정
message = b'Information security and Programming, Test Message!!! Name : Park Sang-Eun'
hash_Func = SHA512.new()
hash_Func.update(message)
hashOfMsg = hash_Func.digest()
print(hashOfMsg.hex())

message1 = b'Information security and Programming, Test Message!!! Name : Park Sang-Eun'
hash_Func2 = SHA512.new()
hash_Func2.update(message1)
if hashOfMsg.hex() == hash_Func2.hexdigest(): # hex 값과 hex 코드 값을 비교 -> 해시값 일여부 확인
    print("Integrity OK, Correct Hash!!")
else:
    print("Incorrect Hash!!")