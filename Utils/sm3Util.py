import binascii

# 导入国密算法sm4包
from gmssl import sm4, sm3


def sm3_hash(message: bytes):
    """
    国密sm3加密
    :param message: 消息值，bytes类型
    :return: 哈希值
    """

    msg_list = [i for i in message]
    hash_hex = sm3.sm3_hash(msg_list)
    return hash_hex
    # print(hash_hex)

    # bytes2hex(hash_hex);

    # hash_bytes = bytes.fromhex(hash_hex)
    # print(hash_bytes)

    # return bytes.hash
    # return hash


def bytes2hex(bytesData):
    hex = binascii.hexlify(bytesData)
    print(hex)
    print(hex.decode())
    return hex




