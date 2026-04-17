import ctypes
import random
import unittest
import sys

sys.path.insert(0, './aes')

from aes import AES, sub_bytes, inv_sub_bytes, shift_rows, inv_shift_rows, mix_columns, inv_mix_columns, add_round_key

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

class InvShiftRowsTest(unittest.TestCase):
    def test_shift_rows(self):
        for _ in range(3):
            original = random.randbytes(16)

            #C implementation
            c_block = ctypes.create_string_buffer(original)
            rijndael.invert_shift_rows(c_block,0)
            c_result = bytes(c_block)[:16]

            # python implementation
            py_block = [[original[row * 4 + col] for row in range(4)] for col in range(4)]
            inv_shift_rows(py_block)
            py_result = bytes([py_block[col][row] for row in range(4) for col in range(4)])

            self.assertEqual(c_result, py_result)

class MixColumnsTestd(unittest.TestCase):
    def test_mix_columns(self):
        for _ in range(3):
            original = random.randbytes(16)

            #C implementation
            #C implementation
            c_block = ctypes.create_string_buffer(original)
            rijndael.mix_columns(c_block,0)
            c_result = bytes(c_block)[:16]

            # python implementation
            py_block = [[original[row * 4 + col] for row in range(4)] for col in range(4)]
            mix_columns(py_block)
            py_result = bytes([py_block[col][row] for row in range(4) for col in range(4)])

            self.assertEqual(c_result, py_result)

class InvertMixColumnsTestd(unittest.TestCase):
    def test_invert_mix_columns(self):
        for _ in range(3):
            original = random.randbytes(16)

            #C implementation
            c_block = ctypes.create_string_buffer(original)
            rijndael.invert_mix_columns(c_block,0)
            c_result = bytes(c_block)[:16]

            # python implementation
            py_block = [[original[row * 4 + col] for row in range(4)] for col in range(4)]
            inv_mix_columns(py_block)
            py_result = bytes([py_block[col][row] for row in range(4) for col in range(4)])

            self.assertEqual(c_result, py_result)

class AddRoundKeyTest(unittest.TestCase):

    def test_add_round_key(self):
        for _ in range(3):
            random_block = random.randbytes(16)
            random_key = random.randbytes(16)

            #C Implementation
            c_block = ctypes.create_string_buffer(random_block)
            c_key = ctypes.create_string_buffer(random_key)
            rijndael.add_round_key(c_block, c_key, 0)
            c_result = bytes(c_block)[:16]

            # Python implementation
            py_block = [[random_block[row * 4 + col] for row in range(4)] for col in range(4)]
            py_key = [[random_key[row * 4 + col] for row in range(4)] for col in range(4)]
            add_round_key(py_block, py_key)
            py_result = bytes([py_block[col][row] for row in range(4) for col in range(4)])

            self.assertEqual(c_result, py_result)



'''Because expand_key returns a list of 4x4 matrices (in the provided python implementation),
I had a difficult time figuring out how test comparing both implementations. So I used a test key
found in the AES documentation on Apendix A(page 27)
https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
'''
class ExpandKeyTest(unittest.TestCase):

    def test_expand_key(self):
    
        key = bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ])

        expected = bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,
            0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
            0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43,
            0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
            0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e,
            0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
            0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f,
            0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
            0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87,
            0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
            0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd,
            0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
            0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3,
            0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
            0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2,
            0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
            0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21,
            0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,
            0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6
        ])

        # Tell ctypes the return type is a pointer
        rijndael.expand_key.restype = ctypes.c_void_p

        c_key = ctypes.create_string_buffer(key)
        result_ptr = rijndael.expand_key(c_key, 0)
        result = ctypes.string_at(result_ptr, 176)

        self.assertEqual(result, expected)



if __name__ == '__main__':
    unittest.main()



