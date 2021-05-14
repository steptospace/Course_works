import socket
import sys
import time


def client_listener():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('127.0.0.1', 9999))
    client_sock.sendall(b'3420!')
    data = client_sock.recv(1024)
    client_sock.close()
    print('Received', repr(data))

def run_server(port=9999):
    serv_sock = create_serv_sock(port)
    cid = 0
    while True:
        client_sock = accept_client_conn(serv_sock, cid)
        public_key = serve_client(client_sock, cid)
        print (public_key)
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
    run_server()


