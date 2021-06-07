import socket
from Cryptodome.Cipher import AES
import Crypto

def client(public_key, private_key, info_pass):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('127.0.0.1', 53210))
    client_sock.sendall(public_key.exportKey(format='PEM'))
    data = client_sock.recv(256)  # Send session key
    session_key = Crypto.decrypt_message(data, private_key)  # decrypt this key

    print(Crypto.encrypt_message_aes(info_pass, session_key, client_sock))

    data = client_sock.recv(10000000)
    nonce = client_sock.recv(16)
    tag = client_sock.recv(16)

    photo = Crypto.decrypt_message_aes(data, tag, session_key, nonce)  # rows это готовое фото

    data_2 = client_sock.recv(10000)  # добавил
    nonce_2 = client_sock.recv(16)  # добавил
    tag_2 = client_sock.recv(16)  # добавил 05.06

    hash = Crypto.decrypt_message_aes(data_2, tag_2, session_key, nonce_2)  # hash
    client_sock.close()
    print('Received', photo)
    with open("D://project//Course_work//venv//Photo1.jpg", "wb") as f:
        f.write(photo)
    f.close()
    return photo, hash
