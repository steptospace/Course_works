import socket
import sys
import time
from Cryptodome.Cipher import AES
from PIL import Image
import Policemen
import Crypto
import test_server_for_android_app



if __name__ == '__main__':

    private_key_for_app, public_key_for_app = Crypto.generate_keys(bits=2048)
    private_key, public_key = Crypto.generate_keys(bits=2048)
    info_pass, conn = test_server_for_android_app.connect_to_app(public_key_for_app, private_key_for_app) # получили Чип от android app
    #Send CHIP to Server DB

    data, signed_2_db = Policemen.client(public_key, private_key, info_pass)
    #data - photo
    hash_from_app = test_server_for_android_app.Zero_knowladge_proof(data, conn) #photo
    signed = test_server_for_android_app.generate_passport_signed(hash_from_app)
    #check signed
    if signed_2_db == signed:
        print("Correct answer: well we do that (^_^)")
        #read the image
        im = Image.open("Photo1.jpg")
        #show image
        im.show()


