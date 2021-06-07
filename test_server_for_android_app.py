import socket
import random
import Crypto
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Random
from Cryptodome.Hash import SHA256, SHA1
from Cryptodome.Signature import pss

from base64 import b64decode
from base64 import b64encode

import hashlib

# Тест
#ip = "192.168.31.151"
ip = "192.168.0.152"
port = 8080

# RSA
# Генерация ключей RSA
def generate_RSA(bits):
    new_key = RSA.generate(bits)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return private_key, public_key
# Шифрование RSA
def encryptRSA(key, plaintext):
    pubkey = RSA.importKey(b64decode(key))
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
    encrypted = cipher.encrypt(plaintext)
    return b64encode(encrypted)
# Расшифрование RSA
def decryptRSA(private_key, ciphertext):
    rsa_key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(b64decode(ciphertext))
    return decrypted

# AES
bs = 16
key = hashlib.sha256("Hello".encode()).digest()

def _pad(s):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def _unpad(s):
    return s[:-ord(s[len(s)-1:])]

# Зашифрование AES
def encryptAES(message, key):
    message = _pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(message.encode()))

# Расшифрование AES
def decryptAES(enc, key):
    enc = b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')



def connect_to_app ():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(10)
    print('Server:', ip, port)
    # Генерация ключ-пары
    private_key, public_key = generate_RSA(bits=2048)

    pubKeyStr = public_key.decode("utf-8")
    pubKeyStr = pubKeyStr.replace("-----BEGIN PUBLIC KEY-----\n", "")
    pubKeyStr = pubKeyStr.replace("-----END PUBLIC KEY-----", "")

    while (True):
        # Подключение клиента
        conn, addr = sock.accept()
        print('Connected: ', addr)
        # Получение от клиента запроса GiveKey
        giveKey = conn.recv(1000)
        print(giveKey)
        # Отправка клиенту публичного ключа
        conn.send(pubKeyStr.encode())
        print("PublicKey sended")
        # Получение от клиента сеансового ключа
        encryptedSessionKey = conn.recv(60000)
        session_key = decryptRSA(private_key, encryptedSessionKey)
        # Ставим новый сеансовый ключ
        key = hashlib.sha256(session_key).digest()
        # Отправка зашифрованного подтверждения
        encOk = encryptAES("ok", key)
        conn.send(encOk)
        print("ok sended")

        # Ожидание второго подключения клиента (вообще можно сохранять ip, чтобы
        # дифференцировать имеешь ли ты с этим клиентом ключ или нет)
        conn, addr = sock.accept()

        # Получение от клиента запроса на сверку данных - CheckInfo
        encCheckInfo = conn.recv(1000)
        сheckInfo = decryptAES(encCheckInfo, key)
        print(сheckInfo)
        # Уведомление клиента о получении запроса
        encOk = encryptAES("ok", key)
        conn.send(encOk)
        print("ok sended")
        # Получение от клиента номера чипа
        encChipId = conn.recv(1000)
        chipId = decryptAES(encChipId, key)
        print("CHIP:")
        print(chipId)
        return chipId.encode(), conn, key

def Zero_knowladge_proof (data, conn, key):
    #data - bytes
    # Отправка клиенту хеша картинки
    ####
    print ("Starting new connection: get data from DB")
    while (True):
        h = SHA256.new()
        h.update(data)
        byte_hash = h.hexdigest().encode()
        print(h.hexdigest())
        enc_all_info = encryptAES(byte_hash.decode('utf-8'), key)
        conn.send(enc_all_info)
        # Получение от клиента остальной инфы
        dummy = conn.recv(60000)
        allInfo = decryptAES(dummy, key)
        print("REST INFO:")
        print(allInfo)
        return (allInfo.encode())

def generate_passport_signed (dummy):
    #Генерация хешей подписи
    passport_info = dummy.decode("utf-8")
    elem_info = passport_info.split("\n")
    print (elem_info[0:10])
    hash_elem_string = ''
    for hash_elem in elem_info[0:10]:
        hash_elem_string += hash_elem
    print(hash_elem_string)
    hash_elem_string = hash_elem_string.encode()
    h = SHA256.new()
    h.update(hash_elem_string) #signed_1
    byte_hash_signed_1 = h.hexdigest().encode()
    print(h.hexdigest())
    h.update(byte_hash_signed_1) #signed_2
    byte_hash_signed_2 = h.hexdigest().encode() # Сравнить с тем что пришло от Олега
    print (byte_hash_signed_2)
    return byte_hash_signed_2

