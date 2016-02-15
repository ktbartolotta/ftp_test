import ftplib
import ftputil
import ftputil.session
import hashlib
import os
import time
import argparse

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

    with ftp.open(file_name, 'rb') as fobj:

        buffer = fobj.read()

    return buffer


def test_file(ftp, file_name, password):

    decrypt_file(
            get_file_data(ftp, file_name), file_name[:-4], password)


def main():

    start = time.time()
    out_dir = '../../FNDecrypted_W_Util'
    password = b'TalenExp0rt!December2015'

    my_session = ftputil.session.session_factory(base_class=ftplib.FTP_TLS)

    with ftputil.FTPHost(
                host='ec2-52-21-101-249.compute-1.amazonaws.com',
                user='Admin', password='8Q674nsPYk452FGt9ye5',
                session_factory=my_session
            ) as ftp:

        for root, dirs, files in ftp.walk('Encrypted_Export'):
            for f in files:
                file_name = ftp.path.join(root, f)
                print(file_name)
                decrypt_file(
                    get_file_data(ftp, file_name),
                    os.path.join(out_dir, f[:-4]),
                    password)

            # file_name = r'Encrypted_Export/B200226_37646-REN.TIF.enc'
            # decrypt_file(
            #     get_file_data(ftp, file_name),
            #     os.path.join(out_dir, 'B200226_37646-REN.TIF'),
            #     password)

    print(time.time() - start)


if __name__ == '__main__':

    # main()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--ftp', help='Decrypt directory or file from an ftp site.',
        nargs=3, metavar=('HOST', 'USERID', 'PASSWORD'))
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-d', '--dir',
        help='''Recursively decrypt all files in directory SOURCE and
                place in directory TARGET.''',
        nargs=2, metavar=('SOURCE', 'TARGET'))
    group.add_argument(
        '-f', '--file',
        help='Decrypt file SOURCE and place in TARGET.', nargs=2,
        metavar=('SOURCE', 'TARGET'))
    args = parser.parse_args()

    if args.ftp:
        print(args.ftp)
    else:
        print('not ftp\'ing')

    if args.dir:
        print(args.dir)
    else:
        print(args.file)
