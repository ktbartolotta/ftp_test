import ftplib
import binascii
import hashlib
import os
import time

from Crypto.Cipher import AES


def pad(data_str):

    return data_str + (16 - len(data_str) % 16) * chr(16 - len(data_str) % 16)


def unpad(data_str):

    return data_str[0:-ord(data_str[-1])]


def decrypt_file(data, out_file, password):

    salt = data[:16]
    iv = data[16:32]
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 65536, 16)
    dec_obj = AES.new(key, AES.MODE_CBC, iv)

    with open(out_file, 'wb') as out_file:

        out_file.write(unpad(dec_obj.decrypt(data[32:])))


def get_file_data(ftp, file_name):

    buffer = []

    def print_block(block):

        buffer.append(block)

    ftp.retrbinary(
        ' '.join(['RETR', file_name]), print_block)

    return ''.join(buffer)


def test_file(ftp, file_name, password):
    #a = ftp.size(file_name)
    decrypt_file(
            get_file_data(ftp, file_name), file_name[:-4], password)


def main():

    start = time.time()
    out_dir = 'FNDecrypted'
    password = b'TalenExp0rt!December2015'

    ftp = ftplib.FTP_TLS(timeout=10)
    ftp.connect('ec2-52-21-101-249.compute-1.amazonaws.com', port=21)
    ftp.auth()
    ftp.prot_p()
    ftp.login(
        'Admin', '8Q674nsPYk452FGt9ye5')
    ftp.set_debuglevel(0)
    ftp.cwd('Encrypted_Export')
    # test_file(ftp, 'B200226_37646-REN.TIF.enc', password)
    file_names = ftp.nlst()
    for file_name in file_names:
        decrypt_file(
            get_file_data(ftp, file_name),
            os.path.join(out_dir, file_name[:-4]),
            password)
    print(time.time() - start)


if __name__ == '__main__':

    main()
