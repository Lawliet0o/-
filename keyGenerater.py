'''
生成甲与乙的公私钥
生成SM4的对称密钥
'''
import argparse
from Utils.sm2Util import SM2Util
from Cryptodome.Random import get_random_bytes
from base64 import b64encode
parser = argparse.ArgumentParser()
parser.add_argument('-k', default='./SM4Key.txt', type=str)  # 命令行中指定SM4密钥（加密前）位置
parser.add_argument('-jpri', default='./Pri_jia.txt', type=str)  # 命令行中指定甲的私钥位置
parser.add_argument('-jpub', default='./Pub_jia.txt', type=str)  # 命令行中指定甲的公钥位置
parser.add_argument('-pri', default='./Pri_yi.txt', type=str)  # 命令行中指定乙的私钥位置
parser.add_argument('-pub', default='./Pub_yi.txt', type=str)  # 命令行中指定乙的公钥位置

args = parser.parse_args()
pri_jia_path = args.jpri
pub_jia_path = args.jpub
pri_yi_path = args.pri
pub_yi_path = args.pub
sm4key_path = args.k


secret_int = None
e = SM2Util.GenKeyPair(secret_int)
priKey = e[0]
pubKey = e[1]
with open(pri_jia_path, 'w') as x:
    x.write(priKey)
with open(pub_jia_path, 'w') as x:
    x.write(pubKey)
# 该乙了
ee = SM2Util.GenKeyPair(secret_int)
priKey = ee[0]
pubKey = ee[1]
with open(pri_yi_path, 'w') as x:
    x.write(priKey)
with open(pub_yi_path, 'w') as x:
    x.write(pubKey)
# 生成SM4的128位随机密钥
sm4_key_bytes = get_random_bytes(16)  # 16字节，即128位
sm4_key = b64encode(sm4_key_bytes).decode('utf-8')
with open(sm4key_path, "w") as x:
    x.write(sm4_key)
# print(priKey)
# print(pubKey)
