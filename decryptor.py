import hashlib
import binascii
import os
import time
from bytequeue import ByteQueue

from Crypto.Cipher import AES


class Decryptor():

    blocks_passed = 0
    iv = ''
    key = ''
    pad = (chr(x) * x for x in xrange(16))
    checksum = hashlib.sha256()

    def __init__(self, out_file, file_size, password):

        self.out_file = out_file
        self.password = password
        self.file_size = file_size

    def get_checksum(self):

        return self.checksum.hexdigest()

    def unpad(self, data_str):

        return data_str[0:-ord(data_str[-1])]

    def create_key(self, salt):

        self.key = hashlib.pbkdf2_hmac(
            'sha1', self.password, salt, 65536, 16)

    def decrypt(self, data, iv):

        dec_obj = AES.new(self.key, AES.MODE_CBC, iv)
        return dec_obj.decrypt(data)

    def stream_to_file(self, block):

        if self.blocks_passed == 0:
            salt = block.read(16)
            self.create_key(salt)
            print(binascii.hexlify(salt))
            self.blocks_passed += 1
        if self.blocks_passed == 1:
            self.iv = block.read(16)
            print(binascii.hexlify(self.iv))
            self.blocks_passed += 1
        if self.blocks_passed > 1:
            b = block.read(16)
            while(b != ''):
                self.blocks_passed += 1
                print(binascii.hexlify(b))
                data = self.decrypt(b, self.iv)
                if self.blocks_passed == self.file_size:
                    data = self.unpad(data)
                self.out_file.write(data)
                self.checksum.update(data)
                self.iv = b
                b = block.read(16)


class Decryptor_v2():

    blocks_passed = 0
    iv = None
    key = None
    data_buffer = ByteQueue()
    checksum = hashlib.sha256()

    def __init__(self, out_file, file_size, password):

        self.out_file = out_file
        self.password = password
        self.file_size = file_size

    def get_checksum(self):

        return self.checksum.hexdigest()

    def unpad(self, data_str):

        return data_str[0:-ord(data_str[-1])]

    def create_key(self, salt):

        self.key = hashlib.pbkdf2_hmac(
            'sha1', self.password, salt, 65536, 16)

    def decrypt(self, data, iv):

        dec_obj = AES.new(self.key, AES.MODE_CBC, iv)
        return dec_obj.decrypt(data)

    def stream_to_file(self, block):

        self.data_buffer.enqueue(block)
        self.blocks_passed += len(block)

        if not self.key:
            if len(self.data_buffer) >= 16:
                salt = self.data_buffer.dequeue(16)
                self.create_key(salt)
        elif not self.iv:
            if len(self.data_buffer) >= 16:
                self.iv = self.data_buffer.dequeue(16)
        else:
            while len(self.data_buffer) >= 16:
                b = self.data_buffer.dequeue(16)
                data = self.decrypt(b, self.iv)
                if self.blocks_passed == self.file_size:
                    data = self.unpad(data)
                self.out_file.write(data)
                self.checksum.update(data)
                self.iv = b


if __name__ == '__main__':

    password = b'TalenExp0rt!December2015'
    start = time.time()
    with open('exportdata.csv.enc', 'rb') as in_file:

        with open('exportdata.csv', 'wb') as out_file:
            file_size = (os.stat('exportdata.csv.enc').st_size)
            print(file_size)
            decryptor = Decryptor_v2(out_file, int(file_size), password)
            data = in_file.read(16)
            while(data != ''):
                decryptor.stream_to_file(data)
                data = in_file.read(16)
            print(decryptor.get_checksum())
    print(time.time() - start)
