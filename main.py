from Cryptodome.Random import get_random_bytes
from gmssl import sm4
import argparse
from Utils.sm2Util import SM2Util
from Utils.sm4Util import sm4_encode, sm4_decode
from Utils.sm3Util import sm3_hash

# 参数处理
parser = argparse.ArgumentParser()
parser.add_argument('-f', default='./test.txt', type=str)  # 命令行中指定明文位置
parser.add_argument('-k', default='./sm4_key.txt', type=str)  # 命令行中指定SM4密钥（加密前）位置
parser.add_argument('-ck',default='./sm4_key_encrypto.txt',type=str) # 命令行中指定SM4的密钥（加密后）的位置
parser.add_argument('-pri', default='./priKey.txt', type=str)  # 命令行中指定乙的私钥位置
parser.add_argument('-pub', default='./pubKey.txt', type=str)  # 命令行中指定乙的公钥位置
parser.add_argument('-iv', default='./iv.txt', type=str)  # 命令行中指定初始向量位置
parser.add_argument('-c', default='./test_cryp.txt', type=str)  # 命令行中指定密文位置
parser.add_argument('-ha', default='./hash.txt', type=str)  # 命令行中指定哈希文件位置
parser.add_argument('-si', default='./sign.txt', type=str)  # 命令行中指定签名文件位置
parser.add_argument('-jpri',default='./jiaPri.txt',type=str) # 命令行中指定甲的私钥位置
parser.add_argument('-jpub',default='./jiaPub.txt',type=str) # 命令行中指定甲的公钥位置
# 生成SM4的128位随机密钥
# sm4_key_bytes = get_random_bytes(16)  # 16字节，即128位
# sm4_key = b64encode(sm4_key_bytes).decode('utf-8')
# with open("sm4_key.txt", "w") as x:
#     x.write(sm4_key)

args = parser.parse_args()
plain_path = args.f
key_path = args.k
priKey_path = args.pri
pubKey_path = args.pub
iv_path = args.iv
cryp_path = args.c
hash_path = args.ha
sign_path = args.si
jiaPri_path = args.jpri
jiaPub_path = args.jpub
key_encry_path = args.ck
# 获取明文文件以及密钥文件
# with open(file_path, 'r') as file:
#     message = file.read()
# with open(key_path, 'r') as key:
#     sm4_key = key.read()

# 获取乙SM2公私钥对
with open(priKey_path, 'r') as pri:
    priKey = pri.read()
with open(pubKey_path, 'r') as pub:
    pubKey = pub.read()
# 获得SM2对象
sm2 = SM2Util(pri_key=priKey, pub_key=pubKey[2:])
# 加密SM4的密钥
# sm4_key_encrypto = sm2.Encrypt(sm4_key)
# with open("sm4_key_encrypto.txt",'w') as sm4En:
#     sm4En.write(sm4_key_encrypto)

# 对SM4的密钥进行解密
with open("sm4_key_encrypto.txt", 'r') as sm4En:
    sm4_key_encrypto = sm4En.read()
    sm4_key = sm2.Decrypt(sm4_key_encrypto)

print("未解密的SM4密钥为：" + sm4_key_encrypto)
print("解密过后的SM4密钥为" + sm4_key)
# 保存解密过后的密钥
with open("sm4_key.txt", 'w') as x:
    x.write(sm4_key)

# 使用获得的SM4密钥来解密文件
# 读取密文
with open(cryp_path, 'r') as x:
    cryp = x.read()
# 获取初始向量文件
with open(iv_path, 'r') as x:
    iv = x.read()
# 解密
message = sm4_decode(sm4_key, cryp, iv)
print("原密文为：" + cryp)
print("解密过后的明文为：" + message)
# 保存解密的明文
with open("message.txt", 'w') as x:
    x.write(message)

# 下面对甲的签名进行验证
# 获取签名文件

with open(sign_path, 'r') as x:
    sign = x.read()
# 获取哈希值
hashCode = sm3_hash(message.encode())
# 获取甲的公钥
with open(jiaPub_path,'r') as x:
    jiaPub = x.read()

jiaVery = SM2Util(pub_key=jiaPub[2:])
check=jiaVery.Verify(hashCode,sign)
# with open(hash_path, 'r') as x:
#     hashCode = x.read()
# 输出验证结果
print("签名验证的结果为："+str(check))

# 检验恢复过后的明文和原来的明文是否一致
# 获取原来的明文
with open(plain_path, 'r') as x:
    plain = x.read()
if message == plain:
    print("一致性检测的结果为：success")
else:
    print("一致性检测的结果为：failure")

# 甲使用乙的公钥对SM4密钥进行加密
# sm4EnCry = SM2Util(pub_key=pubKey)
# key_crypto = sm4EnCry.Encrypt(sm4_key)
# with open(key_encry_path,'w')as x:
#     x.write(key_crypto)
# print(key_crypto)

# 生成甲的公私钥对
# e = SM2Util.GenKeyPair(None)
# # 保存甲的公私钥对
# with open("jiaPri.txt",'w') as x:
#     x.write(e[0])
#
# with open("jiaPub.txt",'w') as x:
#     x.write(e[1])
#

#获取甲的公私钥，以对明文哈希值进行签名
# with open(jiaPri_path,'r') as x:
#     jiaPri = x.read()
# with open(jiaPub_path,'r') as x:
#     jiaPub = x.read()
# jiaSign = SM2Util(pri_key=jiaPri,pub_key=jiaPub[2:])
# # 获取明文的哈希值
# plainHash = sm3_hash(plain.encode())
# jiaSign_str = jiaSign.Sign(plainHash)
# # 将签名文件写入文件中
# with open(sign_path,'w')as x:
#     x.write(jiaSign_str)
# print(jiaSign_str)
#
# jiaVery = SM2Util(pub_key=jiaPub[2:])
# ch=jiaVery.Verify(plainHash,jiaSign_str)
# print(ch)
# # 甲计算明文的哈希值
# message_bytes = message.encode()
# message_hash = sm3_hash(message_bytes)
# # 甲对哈希值进行签名
# sign_hash = sm2.Sign(message_hash)
# print(sign_hash)
# # 写入文件
# with open("sign.txt",'w')as x:
#     x.write(sign_hash)

# 生成初始向量文件
# iv_bytes = get_random_bytes(16)
# iv = b64encode(iv_bytes).decode('utf-8')
# with open('iv.txt','w') as x:
#     x.write(iv)

# 甲使用SM4对明文以及密钥进行加密，并写入文件
# 获取初始向量文件
# with open(iv_path,'r') as x:
#     iv = x.read()
# # 加密，写入文件
# test_cryp = sm4_encode(sm4_key,plain,iv)
# with open("test_cryp.txt",'w') as x:
#     x.write(test_cryp)
# print(message)
# print(test_cryp)


# crypt_message = sm4_encode(sm4_key,message,iv)
# 生成CBC模式的初始化向量IV
# iv = get_random_bytes(16)

# secret_int = None
# priKey,pubKey = SM2Util.GenKeyPair(secret_int)
# e = SM2Util.GenKeyPair(secret_int)
# priKey = e[0]
# pubKey = e[1]
# with open("priKey.txt","w") as pri:
#     pri.write(priKey)
# with open("pubKey.txt","w") as pub:
#     pub.write(pubKey)
# print(priKey)# print(e[0])
#
# print(e[1])
# print(pubKey)

# data = "Hello, World! This is a test for SM4 encryption and decryption."

# endata = sm4_encode(sm4_key, data)
# dedata = sm4_decode(sm4_key, endata)
# sm2 = SM2Util(pri_key=e[0], pub_key=e[1][2:])
# endata = sm2.Encrypt(message)
# print(endata)
# dedata = sm2.Decrypt(endata)
# print(dedata)
# print(data)
# print(endata)
# print(dedata)

# print(e[1][2:])
