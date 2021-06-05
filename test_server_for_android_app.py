import socket
import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA1
from Cryptodome.Signature import pss

# Тест
ip = "192.168.31.151"
port = 8080


def connect_to_app(public_key,private_key):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(10)
    print('Server:', ip, port)

    while (True):
        conn, addr = sock.accept()
        print('Connected: ', addr)
        # Получение от клиента GiveKey
        dummy = conn.recv(1000)
        print(dummy)
        # Отправка клиенту key
        key = public_key.export_key('PEM')
        keyinstring = key.decode("utf-8")
        keyinstring = keyinstring.replace("-----BEGIN PUBLIC KEY-----\n", "")
        keyinstring = keyinstring.replace("-----END PUBLIC KEY-----", "")
        conn.send(keyinstring.encode())
        print("sended key")
        # Получение от клиента сессионного ключа
        dummy = conn.recv(100)
        conn.send(b"ok")
        print("ok sended")
        # Получение от клиента запроса на сверку данных - CheckInfo
        conn, addr = sock.accept()
        dummy = conn.recv(100)
        print(dummy)
        # Уведомление клиента о получении запроса
        conn.send(b"ok")
        # Получение от клиента номера чипа
        dummy = conn.recv(100)
        print("CHIP:")
        print(dummy)
        print ("Connection close: set CHIP id")
        return dummy, conn

def Zero_knowladge_proof (data, conn):
    #data - bytes
    # Отправка клиенту хеша картинки
    ####
    print ("Starting new connection: get data from DB")
    while (True):
        h = SHA256.new()
        h.update(data)
        byte_hash = h.hexdigest().encode()
        print(h.hexdigest())
        conn.send(byte_hash)
        # Получение от клиента остальной инфы
        dummy = conn.recv(100)
        print("REST INFO:")
        print(dummy)
        return (dummy)

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

