#ellipctic curve define on the finite field
from hashlib import sha256
from unittest import TestCase
from ecc import FieldElement, Point, S256Point, G, N, PrivateKey, Signature
from helper import hash256, encode_base58

class ECCTest(TestCase):

    def test_on_curve(self):
        prime = 223
        a = FieldElement(0,prime)
        b = FieldElement(7,prime)
        valid_point = ((192, 105), (17, 56), (1, 193))
        invalid_point = ((200, 119), (42, 99))
        for x_raw, y_raw, in valid_point:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            Point(x, y, a, b)

        for x_raw, y_raw, in invalid_point:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)
    
    def test_add(self):
        prime = 223
        a = FieldElement(0,prime)
        b = FieldElement(7,prime)
        valid_point = ( ((170, 142), (60, 139)), ((47, 71),(17,56)), ((143, 98),   (76,66)))
        for P1_raw, P2_raw, in valid_point:
            x = FieldElement(P1_raw[0], prime)
            y = FieldElement(P1_raw[1], prime)
            P1 = Point(x, y, a, b)
            x = FieldElement(P2_raw[0], prime)
            y = FieldElement(P2_raw[1], prime)
            P2 = Point(x, y, a, b)
            print(P1+P2)

    def test_scalar_multiply(self):
        prime = 223
        a = FieldElement(0,prime)
        b = FieldElement(7,prime)
        x = FieldElement(15, prime)
        y = FieldElement(86, prime)
        P1 = Point(x, y, a, b)
        A = P1
        for i in range(22):
            print(i*P1)
            
    def test_signature_verification(self):
        z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423              #signature hash given by signatory
        r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6              #r as signature
        s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec              #s as signature
        px = 0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574             #x value of puplic key P
        py = 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4             #y value of puplic key P
 
        #first, we need to calc u=z/s, v=r/s. To do this, 1/s is calculated as s_inv. Using Fermat's Little Theorem (n^(p-1)%p = 1) -> s^(-1) = s^(p-2)
        s_inv = pow(s, N-2, N)                          #pow(a,b,c) is difined as (a^b)%c, N is order of the group and also prime number.
        u = z * s_inv % N                               #u = z/s
        v = r * s_inv % N                               #v = r/x
        
        P = S256Point(px, py)
        print((u*G + v*P).x.num == r)                   #uG+vP = R, So do x value of R and r match?
    
    def test_signature_verification2(self):
        P = S256Point(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
            0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)

        # signature 1
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        s_inv = pow(s, N-2, N)
        u = z * s_inv % N
        v = r * s_inv % N 
        print((u*G + v*P).x.num == r)

        # signature 2
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        s_inv = pow(s, N-2, N)
        u = z * s_inv % N
        v = r * s_inv % N 
        print((u*G + v*P).x.num == r)


    def test_signature_generation(self):
        e = int.from_bytes(hash256(b'my secret'),'big')                     #generation secrete key
        z = int.from_bytes(hash256(b'my message'),'big')                    #generation signature hash(or message hash)
        k = 1234567890                                                      #k must be real random number, but use fixed number for test

        R = k * G
        r = R.x.num                                                         #one of the elements of the signature
        k_inv = pow(k,N-2,N)
        s = (z+ r*e) * k_inv % N                                            #s = (z + re)/k

        P = e * G                                                           #public key
        # print("z = ",format(hex(z)))
        # print("r = ",format(hex(r)))
        # print("s = ",format(hex(s)))
        sig = S256Point(r,s)
        print(sig)

    def exercise3p6(self):
        #verify the given signature whether is true
        point = (
        0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 
        0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
        # signature 1
        z1 = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        sig1 = Signature(r,s)
        # signature 2
        z2 = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        sig2 = Signature(r,s)
        
        print(S256Point(point[0],point[1]).verify(z1,sig1))
        print(S256Point(point[0],point[1]).verify(z2,sig2))
        

    def exercise3p7(self):
        #generate signature when private key e=12345, and message = 'Programming Bitcoin!'
        e = 12345
        print(hash256(b'Programming Bitcoin!'))
        z = int.from_bytes(hash256(b'Programming Bitcoin!'), 'big')
        signature_r_s = PrivateKey(secret = e).sign(z)
        print(signature_r_s)

    def exercise4p4(self):
        #convert bellow hexidecimal valie to bytes and encode uinsg BASE58
        h = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
        b = bytes.fromhex(h)
        print(encode_base58(b))

        # check below to see how to base58 working
        '''
        # a = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        # while a > 0 :
        # ...     a, mod = divmod(a,58)
        # ...     print(a,mod)
        # ... 
        # 967240237952588750129842893896793032097560081196520788859379587687447332556 5
        # 16676555826768771553962808515461948829268277262008979118265165304955988492 20
        # 287526824599461578516600146818309462573590987276016881349399401809586008 28
        # 4957359044818303077872416324453611423682603228896842781886196582923896 40
        # 85471707669281087549524419387131231442803503946497289342865458326274 4
        # 1473650132228984268095248610122952266255232826663746367980438936659 52
        # 25407760900499728760262907071085383900952290114892178758283429942 23
        # 438064843112064288970050121915265239671591208877451357901438447 16
        # 7552842122621798085690519343366642063303296704783644101748938 43
        # 130221415907272380787767574885631759712125805254890415547395 28
        # 2245196825987454841168406463545375167450444918187765785299 53
        # 38710290103231980020144939026644399438800774451513203194 47
        # 667418794883310000347326534942144817910358180198503503 20
        # 11507220601436379316333216119692152032937210003422474 11
        # 198400355197178953729883036546416414360986379369353 0
        # 3420695779261706098791086837007179557948041023609 31
        # 58977513435546656875708393741503095826690362476 1
        # 1016853679923218221994972305887984410805006249 34
        # 17531959998676176241292625963585938117327693 55
        # 302275172390968555884355620061826519264270 33
        # 5211640903292561308350958966583215849383 56
        # 89855877642975194971568258044538204299 41
        # 1549239269706468878820142380078244901 41
        # 26711021891490842738278316897900774 9
        # 460534860198117978246177877550013 20
        # 7940256210312378935278928923276 5
        # 136900969143316878194464291780 36
        # 2360361536953739279214901582 24
        # 40695888568167918607153475 32
        # 701653251175308941502646 7
        # 12097469847850154163838 42
        # 208577066342244037307 32
        # 3596156316245586850 7
        # 62002695107682531 52
        # 1069011984615216 3
        # 18431241114055 26
        # 317780019207 49
        # 5478965848 23
        # 94464928 24
        # 1628705 38
        # 28081 7
        # 484 9
        # 8 20
        # 0 8
        '''

        # h = "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c"
        # b = bytes.fromhex(h)
        # print(encode_base58(b))

        # h = "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6"
        # b = bytes.fromhex(h)
        # print(encode_base58(b))
    
    def exercise4p5(self):
        #find public key using bellow secret key and find out bitcoin address
        
        e = 5002                #use testnet and non-compressed SEC
        PublicKey = PrivateKey(secret = e).point
        print(PublicKey)
        b = PublicKey.address(compressed=False, testnet=True)

        # e = 2020**5             #use testnet and compressed SEC
        # PublicKey = PrivateKey(secret = e).point
        # print(PublicKey.address(compressed=True, testnet=True))
        
        # e = 0x12345deadbeef     #use mainnet and compressed SEC
        # PublicKey = PrivateKey(secret = e).point
        # print(PublicKey.address(compressed=True, testnet=False))

    def exercise4p6(self):
        #find WIF of bellow secret key
        e = 5003                #use testnet and compressed SEC
        priv = PrivateKey(e)
        print(priv.wif(compressed=True, testnet=True))

        e = 2021**5             #use testnet and non-compressed SEC
        print(PrivateKey(e).wif(compressed=False, testnet=True))
        e = 0x54321deadbeef     #use mainnet and compressed SEC
        print(PrivateKey(e).wif(compressed=True, testnet=False))

    def exercise4p789(self):

        def little_endian_to_int(b):
            return int.from_bytes(b,'little')

        def int_to_little_endian(i,length):
            return i.to_bytes(length,'little')
        
        my_secret_bytes = b'5hayoung_bitcoin_practice my secret'
        e = little_endian_to_int(hash256(my_secret_bytes))
        PublicKey = PrivateKey(e).point
        my_testnet_address = PublicKey.address(compressed=True, testnet=True)
        print(my_testnet_address)

    def exercise5p5(self):
        hex_transaction = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600'
        from tx import Tx
        from io import BytesIO

        stream = BytesIO(bytes.fromhex(hex_transaction))
        tx_obj = Tx.parse(stream)
        # print(tx_obj.tx_inputs[1].script_sig)
        # print(tx_obj.tx_outputs[0].script_pubkey)
        # print(tx_obj.tx_outputs[1].amount)

    def example_p175(self):
        """
        p2pk is pay to pubkey. It's combinination of lock and unlock script.
        composition of p2pk : ScriptPubKey (<pubkey> + OP_CHECKSIG) + ScriptSig (<signature>)
        remember ECDSA sugnature varification. we need message z and publickey P, and sig(r,s)
        indeed in real BTC the lock & unlock script operate separately to avoid critical problem.
        """
        from script import Script
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d              #hashed message z
        #public key P using non-compressed SEC
        sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')    
        #sig(r,s) using DER
        sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')                                                                             
        script_pubkey = Script([sec, 0xac])                                                 #sec = <pubkey>, 0xac = 172 is opcode of OP_CHECKSIG
        script_sig = Script([sig])                                                          #sig = <signature>
        combined_script = script_sig + script_pubkey 
        print(combined_script.evaluate(z))
    
    def exercise_6p3(self):
        from script import Script
        # 76 76 95 93 56 87
        script_pubkey = Script([0x76,0x76,0x95,0x93,0x56,0x87])
        script_sig = Script([0x52])
        combined_script = script_sig + script_pubkey 
        print(combined_script.evaluate(None))
    
    def example_p195(self):
        from tx import Tx
        from io import BytesIO
        raw_tx = ('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(bytes.fromhex(raw_tx))
        transaction = Tx.parse(stream)
        print(transaction.fee() >= 0)

    def example_p196(self):
        from ecc import S256Point, Signature
        # sec -> P, der -> sig(r,s), z -> z
        sec = bytes.fromhex('0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        der = bytes.fromhex('3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed')
        z = 0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6
        point = S256Point.parse(sec)
        signature = Signature.parse(der)
        print(point.verify(z, signature))

    def example_p200(self):
        from helper import hash256
        modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
        h256 = hash256(modified_tx)
        z = int.from_bytes(h256, 'big')
        print(hex(z))

    def example_p200_2(self):
        from ecc import S256Point, Signature
        sec = bytes.fromhex('0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        der = bytes.fromhex('3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed')
        z = 0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6
        point = S256Point.parse(sec)
        signature = Signature.parse(der)
        print(point.verify(z, signature))
    
    def code_p207(self):
        # generating new Tx with 1 input and 2 output
        from helper import decode_base58, SIGHASH_ALL
        from script import p2pkh_script, Script
        from tx import TxIn, TxOut, Tx
        # 1. generate input 
        prev_tx = bytes.fromhex('0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299')
        prev_index = 13
        tx_in = TxIn(prev_tx, prev_index)
        # 2. generate 1st output : set amount and ScriptPubKey we gained
        tx_outs = []
        change_amount = int(0.33*100000000)             # amount in satoshi unit. 1 BTC = 100000000 satoshi
        change_h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        change_script = p2pkh_script(change_h160)
        change_output = TxOut(amount=change_amount, script_pubkey=change_script)
        # 3. generate 2nd output : set amount and ScriptPubKey we gained
        target_amount = int(0.1*100000000)  
        target_h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        target_script = p2pkh_script(target_h160)
        target_output = TxOut(amount=target_amount, script_pubkey=target_script)
        # 4. generate Tx using testnet=True. now ScriptSig(unlock) in the input is still empty
        tx_obj = Tx(version=1, tx_inputs=[tx_in], tx_outputs=[change_output, target_output], locktime=0, testnet=True)
        print(tx_obj)


        """code_p208, generating ScriptSig(unlock)"""
        transaction = tx_obj
        from ecc import PrivateKey
        from helper import SIGHASH_ALL
        z = transaction.sig_hash(0)                     # since out Tx has only one input, the input_index = 0
        private_key = PrivateKey(secret=8675309)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')      # set hash type to SIGHASH_ALL
        sec = private_key.point.sec()
        script_sig = Script([sig, sec])                 # p2pkh ScriptSig(unlock) = <signature> + <pubkey>
        transaction.tx_inputs[0].script_sig = script_sig   # if there are multiple inputs, generating each ScriptSig and insert to each inputs
        print(transaction.serialize().hex())
        

    def exercise7p4(self):
        """
        Create a testnet Tx that uses 1 UTXO to be used and sends 60% of its face value to the address mwJ~~. 
        The remaining amount after subtracting the fee must be sent back to yout address (TX with 1 input and 2 outputs)
        """

        from helper import little_endian_to_int
        from helper import decode_base58, SIGHASH_ALL
        from script import p2pkh_script, Script
        from tx import TxIn, TxOut, Tx

        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'

        # 1. create my adress
        my_secret_bytes = b'5hayoung_bitcoin_practice my secret'
        e = little_endian_to_int(hash256(my_secret_bytes))
        PublicKey = PrivateKey(e).point
        my_testnet_address = PublicKey.address(compressed=True, testnet=True)
        # print(my_testnet_address) = mwL262B5vr7uQx5P82zqcDGJ7kcWDZEDVp
        # get 0.0001 tBTC = 10000.0 satoshi

        # 2. generate input 
        UTXO_from_cite = "0b649dbf992fcb2ee9e2696d8dc4731ecf36e613174358a3c5d6eecb22ec90cc"
        prev_tx = bytes.fromhex(UTXO_from_cite)
        prev_index = 1
        tx_in = TxIn(prev_tx, prev_index)
        # 3. generate 1st output : set amount and ScriptPubKey we gained
        tx_outs = []
        change_amount = int(500)            
        change_h160 = decode_base58(target_address)
        change_script = p2pkh_script(change_h160)
        change_output = TxOut(amount=change_amount, script_pubkey=change_script)
        # 3-2. generate 2nd output : set amount and ScriptPubKey we gained
        target_amount = int(500)  
        target_h160 = decode_base58(my_testnet_address)
        target_script = p2pkh_script(target_h160)
        target_output = TxOut(amount=target_amount, script_pubkey=target_script)
        # 4. generate Tx using testnet=True. now ScriptSig(unlock) in the input is still empty  
        tx_obj = Tx(version=1, tx_inputs=[tx_in], tx_outputs=[change_output, target_output], locktime=0, testnet=True)
        print(tx_obj.sign_input(input_index=0, private_key=e))
        print(tx_obj.verify())
        print(tx_obj.serialize().hex())

        # pushed the Tx to block check: https://live.blockcypher.com/btc-testnet/tx/b76ccad1ea0d3e77db4354490059f0130c99ed5f9d71ebc7651fd5bf2c4226cb/

    def exercise7p5(self):
        """
        get more tBTC from faucet cite and send the newly gained and remain tBTC to your address
        (TX with 2 inputs and 1 output)
        """
        from helper import little_endian_to_int
        from helper import decode_base58, SIGHASH_ALL
        from script import p2pkh_script, Script
        from tx import TxIn, TxOut, Tx

        my_secret_bytes = b'5hayoung_bitcoin_practice my secret'
        e = little_endian_to_int(hash256(my_secret_bytes))
        change_amount = 400
        my_adress = "mwL262B5vr7uQx5P82zqcDGJ7kcWDZEDVp"

        # input
        UTXO_from_cite1 = "0b649dbf992fcb2ee9e2696d8dc4731ecf36e613174358a3c5d6eecb22ec90cc"
        UTXO_from_cite2 = "8b612870c0db1412632a01cd71081d2e72ca4abbbedf9091481ac94303dc0d0f"
        prev_tx1 = bytes.fromhex(UTXO_from_cite1)
        prev_tx2 = bytes.fromhex(UTXO_from_cite2)
        tx_inputs = [TxIn(prev_tx1,1), TxIn(prev_tx2,1)]
        # output
        h160 = decode_base58(my_adress)
        script_pubkey = p2pkh_script(h160)
        tx_outputs =[TxOut(amount=change_amount, script_pubkey=script_pubkey)]
        # mk Tx
        tx_obj = Tx(1, tx_inputs, tx_outputs, 0, True)
        print(tx_obj.sign_input(0,e))
        print(tx_obj.sign_input(1,e))
        print(tx_obj.serialize().hex())


from helper import run
# run(ECCTest('test_add'))
# run(ECCTest('test_scalar_multiply')):q!
# run(ECCTest('test_signature_verification2'))
# run(ECCTest('test_signature_generation'))
# run(ECCTest('exercise4p4'))
# run(ECCTest('code_p207'))
#run(ECCTest('example_p200_2'))
run(ECCTest('exercise7p5'))