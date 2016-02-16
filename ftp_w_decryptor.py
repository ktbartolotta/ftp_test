import ftplib
import binascii
import hashlib
import os
import time
import pprint
import re
import csv

from decryptor import Decryptor_v2
from ftp_south import FTPSouth
from Crypto.Cipher import AES
from io import BytesIO


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


def get_file_data(ftp, decryptor, file_name):

    ftp.retrbinary(
        ' '.join(['RETR', file_name]), decryptor.stream_to_file, 16)


def download_and_decrypt_file(ftp, file_name, out_dir, file_size, password):

    with open(os.path.join(out_dir, file_name[:-4]), 'wb') as out_file:

        decryptor = Decryptor_v2(out_file, file_size, password)
        get_file_data(ftp, decryptor, file_name)


def get_file_list(ftp):

    file_list = []
    ftp.retrlines('LIST', file_list.append)
    space_match = re.compile(r'\s+', re.IGNORECASE)
    return {y[8]: int(y[4]) for y in (space_match.split(x) for x in file_list)}


def get_csvs(ftp, file_list, password):

    csv_map = {
        k: v for k, v in file_list.iteritems() if 'csv' in k.split('.')}
    csv_readers = []
    for k, v in csv_map.iteritems():
        data = BytesIO()
        decryptor = Decryptor_v2(data, v, password)
        get_file_data(ftp, decryptor, k)
        reader = csv.DictReader(data.getvalue().split('\n'))
        csv_readers.append(reader)
        if 'DocumentClass' in reader.fieldnames:
            csv_readers.append(reader)

    return csv_readers


def main():

    start = time.time()
    out_dir = '../../FNDecrypted_W_Decryptor'
    password = b'xxxxxxxxxxxxx'

    # ftp = ftplib.FTP_TLS(timeout=10)
    # ftp.connect('ec2-52-21-101-249.compute-1.amazonaws.com', port=21)
    # ftp.auth()
    # ftp.prot_p()
    # ftp.login(
    #     'Admin', '8Q674nsPYk452FGt9ye5')
    # ftp.set_debuglevel(0)
    with FTPSouth('ec2-52-21-101-249.compute-1.amazonaws.com',
                  'Admin', 'xxxxxxxxxxxxx', 10) as ftp:
        ftp.cwd('Encrypted_Export')
        file_list = get_file_list(ftp)
        # metadata_files = get_csvs(ftp, file_list, password)
        # row_count = 0
        # for metadata_file in metadata_files:
        #     for row in metadata_file:
        #         row_count += 1
        #         file_name = row['DownloadedFileName'].split('\\')[-1] if (
        #             row['DownloadedFileName'].strip()) else (
        #                 row['ContentFileName'])
        #         if file_name in file_list.keys():
        #             print(file_name)
        for k, v in file_list.iteritems():
            download_and_decrypt_file(ftp, k, out_dir, v, password)

        # get_csvs(ftp, file_list, password)
        # file_name = 'B200226_37646-REN(1).TIF.enc'
        # file_size = file_list[file_name]
        # ftp.quit()
    print(time.time() - start)


if __name__ == '__main__':

    main()
