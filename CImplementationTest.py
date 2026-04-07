import ctypes
import random
import unittest
import sys
from aes import AES, sub_bytes

sys.path.insert(0, './aes')

rijndael = ctypes.CDLL('./rijndael.so')


#implementing first unittest using the TestCase class from the UnitTest framework
#https://docs.python.org/3/library/unittest.html#unittest.TestCase

class SubBytesTest(unittest.TestCase):
    
    def test_sub_bytes(self):
        aes = AES(b'\x00' *16)
        for _ in range(3):
            original = random.randbytes(16)

            #modifying blocks in place (C implementation)
            c_block = ctypes.create_string_buffer(original)
            rijndael.sub_bytes(c_block, 0)
            c_result = bytes(c_block)[:16]


            #Python implementation
            py_block = [list(original[i*4:(i+1)*4]) for i in range(4)]
            sub_bytes(py_block)
            py_result = bytes([py_block[i][j] for i in range(4) for j in range(4)])
            self.assertEqual(c_result, py_result)

if __name__ == '__main__':
    unittest.main()