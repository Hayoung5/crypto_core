# hmac is a module that check message falsification between senders and receivers using hashing.
# https://wikidocs.net/122425

'''
A씨는 B씨에게 인터넷으로 파일을 전달하여 중요한 메시지를 전달하려고 한다. 
하지만 어떤 해커가 A씨가 보낸 파일을 중간에서 가로채어 내용을 바꾼 후에 B씨에게 전달할 가능성이 있다고 한다.
A씨가 보낸 파일이 해커에 의해 변조되었는지 변조되지 않았는지 확인할 수 있는 프로그램을 작성하시오. 
단, 해커가 파일의 내용을 보는 것은 상관이 없고 파일이 변조 되었는지만 검증할 수 있으면 된다.

1. A는 메시지와 공유키로 해싱한 해싱파일, 즉 총 2개의 파일을 B에게 전달.
2. B는 공유키로 원본을 해싱하여 해싱된 파일을 A의 해싱 파일과 비교함으로써 원본이 변조되었는지 확인.
'''

# Step1 (sening example) : make hassing file using hmac with secret key

import hmac
import hashlib

SECRET_KEY = 'PYTHON'

important_message = '이것은 누구나 볼 수 있는 원본 파일의 내용이다.'

with open('message.txt', 'w') as f:
    f.write(important_message)

with open('message_digest.txt', 'w') as f:
    m = hmac.new(SECRET_KEY.encode('utf-8'), important_message.encode('utf-8'),
                 hashlib.sha256)                        # hmac(key, message, hashfunction)
    f.write(m.hexdigest())


# Step 2 (receiving example) : check the message whether falsification

SECRET_KEY = 'PYTHON'

with open('message_digest.txt') as f:
    message_digest = f.read()

with open('message.txt') as f:
    message = f.read()
    m = hmac.new(SECRET_KEY.encode('utf-8'), message.encode('utf-8'),
                 hashlib.sha256)

    if hmac.compare_digest(m.hexdigest(), message_digest):    # Do not use "==" for comparing, use "compare digest(a,b)" to avoid timing attack
        print("메시지가 변조되지 않았습니다. 안전합니다.")              # by avoiding content-based short-circuiting behaviour, 


    else : print("변조된 메시지 입니다.")