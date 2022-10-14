from logging import getLogger       #log reports debug, info, warning, etc. instead of using print(). https://hwangheek.github.io/2019/python-logging/
from helper import encode_varint, int_to_little_endian, read_varint, little_endian_to_int
from op import OP_CODE_NAMES, OP_CODE_FUNCTIONS

LOGGER = getLogger(__name__)

class Script:

    # All commands(cmds) are operators or elements to put on the stack.
    def __init__(self, cmds=None):
        if cmds is None : 
            self.cmds = []
        else: cmds = self.cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)
    
    """
    Need to combine ScriptSig(unlock) and ScriptPubKey(lock). 
    Define add as addition of cmds. then, the commands are processed one by one from the top.
    """
    def __add__(self, other):           
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        length = read_varint(s)         #Script serialization begin with read whole script
        cmds = []
        count = 0
        while count < length :
            current = s.read(1)         #read(n) read stream maximum n bytes
            count += 1 
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75 :       # if 1st byte n is in range [1,75], next n bytes is an element.
                n = current_byte
                cmds.append(s.read(n))                          # append cmds n length element
                count += n
            elif current_byte == 76 :                           # OP_PUSHDATA1(=76) + <len in 1 bytes> + <element> : for 76~255 bytes element
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))   # OP_PUSHDATA2(=77) + <len in 2 bytes> + <element> : for 256~520 bytes element
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:                                               # There is a case of OP_PUSHDATA4(=78), but lets ignore because it is rarely used in practice.
                op_code = current_byte                          # other case, next n bytes is opcode
                cmds.append(op_code)

        if count != length :
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:                                    # in this case, cmd = opcode
                result += int_to_little_endian(cmd, 1)              # convert cmd(int) to_bytes with length 1
            else:                                           
                length = len(cmd)
                if length < 75 :
                    result += int_to_little_endian(length, 1)       # express the length as 1 byte
                elif length > 75 and length < 256:
                    result += int_to_little_endian(76, 1)           # add OP_PUSHDATA1's opcode 76
                    result += int_to_little_endian(length, 1)       # then add the length as 1 byte
                elif length >= 256 and length <= 520:               
                    result += int_to_little_endian(77, 1)           # add OP_PUSHDATA2's opcode 77
                    result += int_to_little_endian(length, 2)       # then add the length as 2 bytes
                else:
                    raise ValueError("too long an cmd")             # infact can handle using OP_PUSHDATA4
            result += cmd
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result                        # place length of serialized script at the front and add  serialzied script
    
    def evaluate(self, z):
        cmds = self.cmds[:]                                         # since cmd is removed one by one from cmds when script operating, copy cmds first.
        stack = []
        altstack = []
        while len(cmds) > 0 :                                       # operating untill all cmd are exhausted
            cmd = cmds.pop(0)                                       # take out "0"th element from cmds and remove from the list.
            if type(cmd) == int:                                    # in this case, cmd = opcode
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99,100):                                 # 99=OP_IF, 100=OP_NOTIF. flow control cmd
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107,108):                              #107=OP_TOALTSTACK, 108=OP_FROMALTSTACK
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:                                                   # in this case, cmd = element, then stack
                stack.append(cmd)
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True


def p2pkh_script(h160):
    # Takes a hash160 and returns the p2pkh ScriptPubKey
    # 0x76=OP_DUP, 0xa9=OP_HASH160, h160, 0x88=OP_EQUALVERIFY, 0xac=OP_CHECKSIG
    return Script([0x76, 0xa9, h160, 0x88, 0xac])