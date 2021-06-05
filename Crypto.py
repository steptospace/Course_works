from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import random


# Напишем функцию для генерации ключей
def generate_keys(bits=2048):
    """Generates the pair of private and public keys."""
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key


private_key, public_key = generate_keys(bits=2048)

'''print(private_key.exportKey(format='PEM').decode())
print('\n')
print('#'*65)
print('\n')
print(public_key.exportKey(format='PEM').decode())
'''
message = b'Hello world!'
session_mess = bytes(41)
messages = "Hello fkng world "


def encrypt_message(message, public_key):
    """Encripts the message using public_key."""
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    print(f'Message: {message} was encrypted to\n{encrypted_message.hex()}')
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message)

def decrypt_message_from_apps(encrypted_message, private_key):
    cipher =  PKCS1_OAEP.new(key = private_key, hashAlgo = SHA256)
    decrypted_message = cipher.decrypt(encrypted_message)
    print(decrypted_message)
    return decrypted_message

def encrypt_hash(messages):  # check this moment and be careful messages only STRING !!!
    data_hash = SHA256.new(messages.encode())
    return data_hash


def gen_session_key():
    key = get_random_bytes(32)
    return key


def decrypt_message_aes(cipher, tag, session_key, nonce):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(cipher, tag)


def encrypt_message_aes(data, session_key, client_sock):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    client_sock.sendall(ciphertext)
    client_sock.sendall(cipher_aes.nonce)
    client_sock.sendall(tag)

