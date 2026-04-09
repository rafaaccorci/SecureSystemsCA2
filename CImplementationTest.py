import ctypes
import random
import unittest
import sys

sys.path.insert(0, './aes')

from aes import AES, sub_bytes, inv_sub_bytes, shift_rows

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


class InvertSubBytesTest(unittest.TestCase):
       
    def test_inv_sub_bytes(self):
        aes = AES(b'\x00' *16)
        for _ in range(3):
            original = random.randbytes(16)

            #modifying blocks in place (C implementation)
            c_block = ctypes.create_string_buffer(original)
            rijndael.invert_sub_bytes(c_block, 0)
            c_result = bytes(c_block)[:16]


            #Python implementation
            py_block = [list(original[i*4:(i+1)*4]) for i in range(4)]
            inv_sub_bytes(py_block)
            py_result = bytes([py_block[i][j] for i in range(4) for j in range(4)])
            self.assertEqual(c_result, py_result)

class ShiftRowsTest(unittest.TestCase):
    def test_shift_rows(self):
        for _ in range(3):
            original = random.randbytes(16)

            #C implementation
            c_block = ctypes.create_string_buffer(original)
            rijndael.shift_rows(c_block,0)
            c_result = bytes(c_block)[:16]

            # python implementation
            py_block = [[original[row * 4 + col] for row in range(4)] for col in range(4)]
            shift_rows(py_block)
            py_result = bytes([py_block[col][row] for row in range(4) for col in range(4)])

            self.assertEqual(c_result, py_result)


if __name__ == '__main__':
    unittest.main()



