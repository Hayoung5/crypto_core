from io import BytesIO
from unittest import TestCase

import json
import requests
from ecc import (
    PrivateKey,
    Signature,
)

from helper import (
    SIGHASH_ALL,
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from script import Script

class Tx:

    def __init__(self, version, tx_inputs, tx_outputs, locktime, testnet=False):
        self.version = version
        self.tx_inputs = tx_inputs
        self.tx_outputs = tx_outputs
        self.locktime = locktime
        self.testnet = testnet                                              #need to know which network generate the Tx to verify Tx
    
    def __repre__(self):
        tx_inputs = ''
        for tx_inputs in self.tx_inputs:
            tx_inputs += tx_inputs.__repre__() + '\n'
        tx_outputs = ''
        for tx_outputs in self.tx_outputs:
            tx_outputs += tx_outputs.__repre__() + '\n'
        return 'tx: {}\nversion: {}\ntx_inputs:\n{}tx_outputs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_inputs,
            tx_outputs,
            self.locktime,
        )

    #id() returns a hash256 value with Tx as input in hex, the value can be used for search of Tx in block explore
    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()
    
    #hash() returns a hash256 value with Tx as input,
    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]
    
    #if serialized Tx is large, the parse method may not be called until the serialization recieved completely
    # @classmethod        #since parse return Tx class's instance
    # def parse(cls, serialization):        
    #     version = serialization[0:4]

    #this method use stream as input instead of bytes type input, This allows figure out parsing errors more quickly.
    @classmethod
    def parse(cls, stream, testnet=False):
        #version part
        serialized_version = stream.read(4)         #start parsing by reading 4 bytes of stream buffer, It is much faster because only the 4 bytes needed are read.
        version = little_endian_to_int(serialized_version)
        #input part
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))
        #output part
        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
        #locktime part
        locktime = little_endian_to_int(stream.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)
    
    def serialize(self):
        """Returns the byte serialization of the transaction"""
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_inputs))
        for tx_in in self.tx_inputs:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outputs))
        for tx_out in self.tx_outputs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result
    
    # the fee is calculated from fee = sum of inputs - sum of outputs
    def fee(self, testnet=False):
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_inputs:
            input_sum += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outputs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    def sig_hash(self, input_index):
        '''
        find hashed message z using step by step method and return integer z
        this method is inefficient because of "quadratic hashing problem
        to follow step by step method, the code recounstruct Tx by putting ScriptPubKey instead of putting ScriptSig.
        '''
        # reconstruct the Tx in the order bellow
        # version + modified input(delete ScriptSig and insert ScriptPubKey) + output+ locktime + type of hash(in this code, we use SIGHASH_ALL)
        s = int_to_little_endian(self.version,4)
        s += encode_varint(len(self.tx_inputs))
        for i, tx_in in enumerate(self.tx_inputs):
            if i == input_index :
                s += TxIn(
                    prev_tx = tx_in.prev_tx,
                    prev_index = tx_in.prev_index,
                    script_sig = tx_in.script_pubkey(self.testnet),         # add ScriptPubKey to space for ScriptSig
                    sequence=tx_in.sequence,
                ).serialize()

            else:               #if i!= input_index, do not insert either ScriptSig and ScriptPubKey
                s += TxIn(
                    prev_tx = tx_in.prev_tx,
                    prev_index = tx_in.prev_index,
                    sequence=tx_in.sequence,                    
                ).serialize()
        s += encode_varint(len(self.tx_outputs))
        for tx_out in self.tx_outputs:
            s+= tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL,4)
        h256 = hash256(s)
        z = int.from_bytes(h256, 'big')
        return z

    def verify_input(self, input_index):
        # Does the unlock script of input “unlock" the referenced Tx output's lock script? -> Check whether combined script is valid
        # make combined script (ScriptSig + ScriptPubKey) and evaluate the combined script using newly found z
        tx_in = self.tx_inputs[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        combined = tx_in.script_sig + script_pubkey
        z = self.sig_hash(input_index)
        return combined.evaluate(z)

    def verify(self):
        '''
        verify one whole Tx, check those conditions (in the case of full node, they check more conditions include double payment...)
        2. Is the fee of the Tx positive?
        3. Does the unlock script of input “unlock" the referenced Tx output's lock script? -> using verify_input()
        '''
        if self.fee() < 0 :
            return False
        for i in range(len(self.tx_inputs)):
            if not self.verify_input(i):
                return False
        return True
    
    def sign_input(self, input_index, private_key, compressed=True):
        z = self.sig_hash(input_index)                                  # get the signature hash (z)
        private_key = PrivateKey(secret=private_key)                    # get der signature of z from private key
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')                      # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sec = private_key.point.sec(compressed)                         # calculate the sec
        self.tx_inputs[input_index].script_sig = Script([sig, sec])     # change input's script_sig to new script
        return self.verify_input(input_index)                           # return whether sig is valid using self.verify_input


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()  #if script_sig is None self.script_sig is initialized to Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repre__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls,s):
        """Takes a byte stream and parses the tx_input at the start. Returns a TxIn object."""
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        """Returns the byte serialization of the transaction input"""
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    # the prev Tx's id is in input of the Tx. this part fetch prev Tx and return amount and ScriptPubKey from output of the Tx.
    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)
    
    # return amount from prev Tx to calc fee
    def value(self, testnet=False):
        """Get the output value by looking up the tx hash. Returns the amount in satoshi"""
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outputs[self.prev_index].amount
    
    def script_pubkey(self, testnet=False):
        """Get the ScriptPubKey by looking up the tx hash. Return a Script object."""
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outputs[self.prev_index].script_pubkey


class TxOut:
    
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repre__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses the tx_output at the start. Returns a TxOut object."""
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)
    
    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

# TxFetcher fetches prev Tx using its id from current Tx's input
# search the prev Tx in search engine
class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockstream.info/testnet/api'
        else:
            return 'https://blockstream.info/api'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/hex'.format(cls.get_url(testnet), tx_id)
            print(url)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:                # Check if the tx hash value (ID) we are looking for is matched and if not an error occurs
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx

        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]


    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)

