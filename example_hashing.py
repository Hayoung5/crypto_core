# Example of hashing string
# https://wikidocs.net/122201
'''
입력한 비밀번호를 passwd.txt 파일에 저장하는 프로그램을 작성하시오. 단, 비밀번호는 유추 및 복호화가 불가능한 sha256방식으로 해싱하여 저장해야 한다.
 그리고 이미 저장된 비밀번호 파일이 있을 경우에는 기존 비밀번호를 입력받아 비밀번호가 일치할 경우에만 새로운 비밀번호를 저장하는 프로그램을 작성하시오.
'''

# basic concept

import hashlib

m = hashlib.sha256()
m.update('Life is too short'.encode('utf-8'))           # hasing string, str.encode('utf-8') transfer unicord strinig to UTF-8 type byte string

m.update(', you need python.'.encode('utf-8'))          # add more words

print(m.digest())                                       # digest with byte string
print(m.hexdigest())                                    # digest as hex string

# the hashing value can not return to original string, since hashing is an one-way encryption algorithm.

# Answer code

import hashlib
import os

def check_passwd():
    if os.path.exists('passwd.txt'):
        before_passwd = input('insert the old password:\n')
        m = hashlib.sha256()
        m.update(before_passwd.encode('utf-8'))
        with open('passwd.txt', 'r') as f:
            return m.hexdigest() == f.read()
    else:
        return True

if check_passwd():
    passwd = input('insert the new password:\n')
    with open('passwd.txt', 'w') as f:
        m = hashlib.sha256()
        m.update(passwd.encode('utf-8'))
        f.write(m.hexdigest())

else:
    print("wrong password!")