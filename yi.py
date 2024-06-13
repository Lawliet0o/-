'''
这部分完成乙的相关工作，包括：
    对加密过后的SM4密钥的解密
    对密文的解密
    对甲签名的确认
    对文件一致性的检验
'''
from Cryptodome.Random import get_random_bytes
from gmssl import sm4
import argparse
from Utils.sm2Util import SM2Util
from Utils.sm4Util import sm4_encode, sm4_decode
from Utils.sm3Util import sm3_hash
parser = argparse.ArgumentParser()
parser.add_argument('-k', default='./SM4Key.txt', type=str)  # 命令行中指定SM4密钥（加密前）位置
parser.add_argument('-ck', default='./sm4_key_encrypto.txt', type=str)  # 命令行中指定SM4的密钥（加密后）的位置
parser.add_argument('-jpub', default='./Pub_jia.txt', type=str)  # 命令行中指定甲的公钥位置
parser.add_argument('-p', default='./plain.txt', type=str)  # 命令行中指定明文的位置
parser.add_argument('-ypri', default='./Pri_yi.txt', type=str)  # 命令行中指定乙的私钥位置
parser.add_argument('-ypub', default='./Pub_yi.txt', type=str)  # 命令行中指定乙的公钥位置
parser.add_argument('-iv', default='./iv.txt', type=str)  # 命令行中指定初始向量位置
parser.add_argument('-c', default='./crypto.txt', type=str)  # 命令行中指定密文位置
parser.add_argument('-si', default='./sign.txt', type=str)  # 命令行中指定签名文件位置

args = parser.parse_args()
pub_jia_path = args.jpub
sm4key_path = args.ck
plain_path = args.p
pub_yi_path = args.ypub
pri_yi_path = args.ypri
iv_path = args.iv
crypto_path =args.c
sign_path = args.si
# 获取乙SM2公私钥对
with open(pri_yi_path, 'r') as pri:
    YpriKey = pri.read()
with open(pri_yi_path, 'r') as pub:
    YpubKey = pub.read()
# 获得SM2对象
sm2 = SM2Util(pri_key=YpriKey, pub_key=YpubKey[2:])

# 对SM4的密钥进行解密
with open(sm4key_path, 'r') as sm4En:
    sm4_key_encrypto = sm4En.read()

sm4_key = sm2.Decrypt(sm4_key_encrypto)
print("未解密的SM4密钥为：" + sm4_key_encrypto)
print("解密过后的SM4密钥为" + sm4_key)

# 保存解密过后的密钥
with open("sm4_key_decrypto.txt", 'w') as x:
    x.write(sm4_key)

# 使用获得的SM4密钥来解密文件
# 读取密文
with open(crypto_path, 'r') as x:
    cryp = x.read()
# 获取初始向量文件
with open(iv_path, 'r') as x:
    iv = x.read()
# 解密
message = sm4_decode(sm4_key, cryp, iv)
print("原密文为：" + cryp)
print("解密过后的明文为：\n" + message)
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
with open(pub_jia_path,'r') as x:
    jiaPub = x.read()

jiaVery = SM2Util(pub_key=jiaPub[2:])
check=jiaVery.Verify(hashCode,sign)
print("签名验证的结果为："+str(check))

# 检验恢复过后的明文和原来的明文是否一致
# 获取原来的明文
with open(plain_path, 'r',encoding='utf-8') as x:
    plain = x.read()
if message == plain:
    print("一致性检测的结果为：success")
else:
    print("一致性检测的结果为：failure")