import socket
import sys
import time
import Policemen





def run_server(port=9999):
    serv_sock = create_serv_sock(port)
    cid = 0
    while True:
        client_sock = accept_client_conn(serv_sock, cid)
        session_key = serve_client(client_sock, cid)
        print(session_key) ### check this is session key
        cid += 1


def serve_client(client_sock, cid):
    request = read_request(client_sock)
    if request is None:
        print(f'Client #{cid} unexpectedly disconnected')
    else:

        write_response(client_sock, request, cid)
        return request


def create_serv_sock(serv_port):
    serv_sock = socket.socket(socket.AF_INET,
                              socket.SOCK_STREAM,
                              proto=0)
    serv_sock.bind(('', serv_port))
    serv_sock.listen()
    return serv_sock


def accept_client_conn(serv_sock, cid):
    client_sock, client_addr = serv_sock.accept()
    print(f'Client #{cid} connected '
          f'{client_addr[0]}:{client_addr[1]}')
    return client_sock


def read_request(client_sock, delimiter=b'!'):
    request = bytearray()
    try:
        while True:
            chunk = client_sock.recv(1)
            if not chunk:
                # Клиент преждевременно отключился.
                return None
            if delimiter in chunk:
                return request
            request += chunk


    except ConnectionResetError:
        # Соединение было неожиданно разорвано.
        return None
    except:
        raise


def write_response(client_sock, response, cid):
    client_sock.sendall(response)
    client_sock.close()
    print(f'Client #{cid} has been served')


if __name__ == '__main__':

    # Начало соединения
    Policemen.client() # отправка Public key
    run_server() # прием session key (Сеансового ключа)

    # Отправка Мише ....
    key = gen_session_key()
    session_key = encrypt_message(key, request)
    print(len(session_key))
    client_sock.sendall(session_key)

    # Прием данных от Олега

    cipher = read_request(client_sock)
    nonce = client_sock.recv(16)
    tag = client_sock.recv(16)
    if cipher is None:
        print(f'Client #{cid} unexpectedly disconnected')
    else:
        message = decrypt_message(cipher, tag, key, nonce)
        rows = handle_request(message, client_sock)
        encrypt_message_AES(rows, key, client_sock)
        client_sock.close()
        print(f'Client #{cid} has been served')

