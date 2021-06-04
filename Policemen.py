import socket
import Crypto


def client():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('127.0.0.1', 9999))
    client_sock.sendall(bytes(Crypto.public_key.exportKey(format='PEM').decode(), 'utf-8') + b'!')
    data = client_sock.recv(2048)
    client_sock.close()
    print('Received', repr(data))
