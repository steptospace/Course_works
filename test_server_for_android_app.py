import socket
import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA1
from Cryptodome.Signature import pss

# Тест 







ip = "192.168.31.151"
port = 8082



def encrypt_message(message, public_key):
    """Encripts the message using public_key."""
    cipher =  PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    print(f'Message: {message} was encrypted to\n{encrypted_message.hex()}')
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    cipher =  PKCS1_OAEP.new(key = private_key, hashAlgo = SHA256)
    decrypted_message = cipher.decrypt(encrypted_message)
    print(decrypted_message)
    return decrypted_message

def generate_keys(bits=2048):
    """Generates the pair of private and public keys."""
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key


private_key, public_key = generate_keys(bits=2048)

print(private_key.exportKey(format='PEM').decode())
print('\n')
print('#'*65)
print('\n')
print(public_key.exportKey(format='PEM').decode())

private_key, public_key = generate_keys(bits = 2048)



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

    # Отправка клиенту хеша картинки
    h = SHA256.new()
    with open("D://project//Course_work//venv//Photo.jpg", "rb") as f:
        data = f.read()
    h.update(data)
    byte_hash = h.hexdigest().encode()
    print(h.hexdigest())
    conn.send(byte_hash)

    # Получение от клиента остальной инфы
    dummy = conn.recv(100)
    print("REST INFO:")
    print(dummy)
    passport_info = dummy.decode("utf-8")
    print(passport_info.split("\n"))
    elem_info = passport_info.split("\n")