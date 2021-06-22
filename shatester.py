import unittest
import pySHA
import random
import string
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512


class SHA1_Test(unittest.TestCase):


    def test_SHA1_abc(self):
        message = 'abc'

        m1 = SHA1.new()
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA1(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()
        
        self.assertEqual(hash1, hash2)


    def test_SHA1_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA1.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA1(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA1_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA1.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA1(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA1_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA1.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA1(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA224_Test(unittest.TestCase):


    def test_SHA224_abc(self):
        message = 'abc'

        m1 = SHA224.new()
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA224(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA224_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA224.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA224_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA224.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA224_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA224.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA256_Test(unittest.TestCase):


    def test_SHA256_abc(self):
        message = 'abc'

        m1 = SHA256.new()
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA256(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA256_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA256.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA256_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA256.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA256_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA256.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA384_Test(unittest.TestCase):


    def test_SHA384_abc(self):
        message = 'abc'

        m1 = SHA384.new()
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA384(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA384_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA384.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA384(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA384_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA384.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA384(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA384_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA384.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA384(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA512_Test(unittest.TestCase):


    def test_SHA512_abc(self):
        message = 'abc'

        m1 = SHA512.new()
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA512(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA512_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA512.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA512_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA512.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA512_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA512.new()
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA512_224_Test(unittest.TestCase):


    def test_SHA512_224_abc(self):
        message = 'abc'

        m1 = SHA512.new(truncate="224")
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA512_224(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA512_224_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA512.new(truncate="224")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA512_224_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA512.new(truncate="224")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA512_224_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA512.new(truncate="224")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_224(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)



class SHA512_256_Test(unittest.TestCase):


    def test_SHA512_256_abc(self):
        message = 'abc'

        m1 = SHA512.new(truncate="256")
        m1.update(message.encode())
        hash1 = m1.hexdigest()

        m2 = pySHA.SHA512_256(verbose=0)
        m2.update(message.encode())
        hash2 = m2.digest()

        self.assertEqual(hash1, hash2)


    def test_SHA512_256_robustness_ascii_chars(self):
        pool = string.ascii_letters + string.punctuation + string.digits
        for _ in range(100):

            message = ''
            for _ in range(500):
                message = message + random.choice(pool)

            m1 = SHA512.new(truncate="256")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)


    def test_SHA512_256_robustness_1(self):
        message = ''
        for i in range(1, 1250, 4):

            message = message + random.choice(string.ascii_letters)

            m1 = SHA512.new(truncate="256")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2, 'Failed with message length: ' + str(len(message)) + ' on iteration ' + str(i) + ' with message ' + message)


    def test_SHA512_256_robustness_2(self):
        for _ in range(25):
            message = ''
            for _ in range(2500):
                message = message + random.choice(string.ascii_letters)
            
            m1 = SHA512.new(truncate="256")
            m1.update(message.encode())
            hash1 = m1.hexdigest()

            m2 = pySHA.SHA512_256(verbose=0)
            m2.update(message.encode())
            hash2 = m2.digest()
            
            self.assertEqual(hash1, hash2)





if __name__ == '__main__':
    unittest.main(verbosity=3)

