'''
在这部分是给甲用的
主要实现对SM4密钥的加密，实现对明文的加密，对明文哈希值的计算，对明文的哈希值进行签名
'''
import argparse
from Utils.sm2Util import SM2Util
from Utils.sm4Util import sm4_encode
from Utils.sm3Util import sm3_hash

parser = argparse.ArgumentParser()
parser.add_argument('-k', default='./SM4Key.txt', type=str)  # 命令行中指定SM4密钥（加密前）位置
parser.add_argument('-ck', default='./sm4_key_encrypto.txt', type=str)  # 命令行中指定SM4的密钥（加密后）的位置
parser.add_argument('-jpri', default='./Pri_jia.txt', type=str)  # 命令行中指定甲的私钥位置
parser.add_argument('-jpub', default='./Pub_jia.txt', type=str)  # 命令行中指定甲的公钥位置
parser.add_argument('-p', default='./plain.txt', type=str)  # 命令行中指定明文的位置
parser.add_argument('-ypub', default='./pub_yi.txt', type=str)  # 命令行中指定乙的公钥位置
parser.add_argument('-iv', default='./iv.txt', type=str)  # 命令行中指定初始向量位置
args = parser.parse_args()
pri_jia_path = args.jpri
pub_jia_path = args.jpub
sm4key_path = args.k
sm4Cryp_key_path = args.ck
plain_path = args.p
pub_yi_path = args.ypub
iv_path = args.iv

# 获取初始向量
with open(iv_path, 'r') as x:
    iv = x.read()
# 获取甲的公私钥
with open(pri_jia_path, 'r') as x:
    JpriKey = x.read()
with open(pub_jia_path, 'r') as x:
    JpubKey = x.read()
# 获取乙的公钥
with open(pub_yi_path, 'r') as x:
    YpubKey = x.read()
# 获得SM2对象,这个对象用乙的公钥来加密SM4密钥
sm2 = SM2Util(pub_key=YpubKey[2:])
# 获取未加密的sm4密钥
with open(sm4key_path, 'r') as x:
    sm4_key = x.read()
# 加密SM4的密钥
sm4_key_encrypto = sm2.Encrypt(sm4_key)
with open("sm4_key_encrypto.txt", 'w') as sm4En:
    sm4En.write(sm4_key_encrypto)

# 下面使用SM4对明文进行加密
# 先获取明文
with open(plain_path, 'r',encoding='utf-8') as x:
    plain = x.read()
# 加密，并写入文件
crypto = sm4_encode(key=sm4_key, data=plain, iv=iv)
with open("crypto.txt",'w')as x:
    x.write(crypto)

# 计算明文的哈希值,并对哈希值进行签名
plain_hash = sm3_hash(plain.encode())
print(plain_hash)
# 甲对哈希值进行签名
# 先生成甲的SM2对象
Jsm2 = SM2Util(pri_key=JpriKey,pub_key=JpubKey[2:])
sign_hash = Jsm2.Sign(plain_hash)
print(sign_hash)
# 写入文件
with open("sign.txt",'w')as x:
    x.write(sign_hash)
