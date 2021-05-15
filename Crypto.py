from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import PKCS1_OAEP

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
messages = "Hello fkng world "


def encrypt_message(message, public_key):
    """Encripts the message using public_key."""
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    print(f'Message: {message} was encrypted to\n{encrypted_message.hex()}')
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    print(decrypted_message)

def encryp_hash (messages): # check this moment and be careful messages only STRING !!!
    data_hash = SHA256.new(messages.encode())
    return data_hash

#decrypt_message(encrypt_message(message, public_key),private_key) ok correctly work

