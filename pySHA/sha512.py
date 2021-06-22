from . import hashframe

SHA_HashFrame = hashframe.SHA_HashFrame
class SHA512(SHA_HashFrame):
    """
    Implements the SHA-512 Algorithm
    """

    def __init__(self, verbose=1):
        self.verbose = verbose

        # SHA-512 uses 1024-bit blocks with 64-bit (long) word sizes
        self.block_size = 1024
        self.word_size = 64
        
        # SHA-512 constants. These are arbitrary in the sense that they are
        # pre-defined in the official specification for the algorithm but 
        # otherwise have no other significant mathematical meaning. These are needed
        # to generate the T1 values in the main hash computation
        constants = """
            428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
            3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
            d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
            72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
            e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
            2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
            983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
            c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
            27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
            650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
            a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
            d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
            19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
            391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
            748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
            90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
            ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
            06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
            28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
            4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
            """

        K = ['0x' + item for item in constants.split()]
        K = [int(item, 0) for item in K]
        self.K = K

        # Initial state variables for SHA-512. Like the constants, these are
        # pre-defined values in the official specification needed to seed the
        # hash values. These are generated from the first 64 bits of the fractional 
        # parts of the square roots of the first 8 prime numbers
        H_init = ["0x6a09e667f3bcc908", "0xbb67ae8584caa73b", "0x3c6ef372fe94f82b", "0xa54ff53a5f1d36f1", "0x510e527fade682d1", "0x9b05688c2b3e6c1f", "0x1f83d9abfb41bd6b", "0x5be0cd19137e2179"]
        self.H0 = [int(item, 0) for item in H_init]
        self.H = [int(item, 0) for item in H_init]
        return


    def __preprocess__(self, message):
        """
        Preprocesses the message by paddding it as appropriate to make the total length
        a multiple of 1024 bits and then splitting it into 1024-bit blocks.
        """
        verbose = self.verbose

        if (verbose > 1):
            print('[SHA-512] Beginning Preprocessing')

        padded_message_bytes = b''
        if type(message) == bytes:
            nbits = len(message) * 8

            if (verbose > 1):
                print('[SHA-512]    Message Length: %d bits'%(nbits))

            # SHA-512 requires the word blocks to be exactly 1024 bits long,
            # in addition to having the message length encoded at the end
            # of the message using 128 bits. Thus, we add 128 to the required
            # bit count for the message length, then round up to 1024 bytes,
            # then pad the zeros and the '1' bit
            num_zeros = 896 - nbits - 1
            while num_zeros > self.block_size: num_zeros -= self.block_size
            while num_zeros < 0: num_zeros += self.block_size

            # The number of zeros to pad with is the smallest nonnegative solution
            # to l + 1 + k ≡ 896 mod 1024, with l = nbits, the total number of bits in
            # the unpadded message.

            if (verbose > 1):
                print("[SHA-512]    Adding a single '1' bit")

            # The 896 comes from the fact that the last 128 bits in the last
            # padded block are reserved to hold the total length of the message.
            # Thus the maximum. (896 + 128 = 1024). Thus, the maximum message size
            # that can be hashed with SHA-512 is 2^128 - 1 bits. Note that after
            # the end of the message, we always add a single '1' bit, which is
            # NOT included in the final 128 bits. The number of zeros is selected
            # such that the last fully padded block is 1024 bytes long, of which the
            # last 128 are reserved.

            byte_array = list(message)
            byte_array.append(1 << 7)

            if (verbose > 1): print("[SHA-512]    Padding %d Zeros"%(num_zeros))
            for _ in range(int((num_zeros - 7) / 8)): byte_array.append(0)
            for item in list(nbits.to_bytes(16, 'big')): byte_array.append(item)
            padded_message_bytes = bytes(byte_array)



        nbits = len(padded_message_bytes) * 8
        blocks = []
        nblocks = int(nbits/self.block_size)

        if (verbose > 1):
            print('[SHA-512]    New Input Length: %d bits'%(8 * len(list(byte_array))))
            print('[SHA-512]    Number of %d-bit Blocks: %d'%(self.block_size, nblocks))

        # Splits the padded message into 512-bit blocks
        for i in range(nblocks):
            start = int(i * self.block_size / 8)
            end = int((i + 1) * self.block_size / 8)
            blocks.append( padded_message_bytes[start : end])

        if (verbose > 1): print('[SHA-512] Preprocessing Complete')
        return blocks


    def __hash__(self, blocks):
        """
        The main hash routine. Accepts the blocks generated from the preprocessing
        routing and computes the SHA-512 hash.
        """
        verbose = self.verbose
        N = len(blocks)

        if (verbose > 1):
            print('[SHA-512] Initializing State Variables H0-H7')
            print('[SHA-512]    H[%2d] = %10s %10s %10s %10s %10s %10s %10s %10s'%(
                      0, '0x' + self.H[0].to_bytes(8, 'big').hex(), '0x' + self.H[1].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(8, 'big').hex(), '0x' + self.H[3].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(8, 'big').hex(), '0x' + self.H[5].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[6].to_bytes(8, 'big').hex(), '0x' + self.H[7].to_bytes(8, 'big').hex()
            ))

        # The algorithm must go through every block, so that a change in any bit
        # changes the hash function output.
        for i in range(N):
            
            if (verbose > 2):
                print('[SHA-512] Iterating through Block %d'%(i))

            # Parse the current block
            block = blocks[i]


            if (verbose > 3):
                print('[SHA-512]    Preparing Message Schedule')

            W = []

            # Prepare the message schedule W. The message schedule for SHA-512 consists 
            # of 64 32-bit integers. The first 16 integers are generated from the block
            # itself, since the block is exactly 512 bits (32 x 16 = 512). Note that this
            # results in a different schedule for each block.

            for j in range(0, 16, 1):
                start = int(self.word_size * j / 8)
                end = int(self.word_size * (j + 1) / 8)
                word =  block[start : end]
                word = int.from_bytes(word, byteorder='big')
                W.append(word)

                if (verbose > 2):
                    print('[SHA-512]        W[%2d]=%10s'%(j, '0x' + word.to_bytes(8, 'big').hex()))

            # The last 64 integers in the message schedule are generated iteratively
            # from the first 16. For each new member j of W, it adds W[j-7], W[j-16],
            # and applies two custom functions sigma0 and sigma1 to W[j-15] and W[j-2]. The
            # specific definitions of these are located in the official specification and
            # reproduced below 

            for j in range(16, 80, 1):
                part1 = self.__sigma1__(W[j-2])
                part2 = self.__sigma0__(W[j-15])
                part3 = W[j-16]
                part4 = W[j-7]

                sum = self.__bitwise_add__(part1, part2)
                sum = self.__bitwise_add__(sum, part3)
                sum = self.__bitwise_add__(sum, part4)
                W.append(sum)

                if (verbose > 2):
                    print('[SHA-512]        W[%2d]=%10s       \
                        <- σ0(W[%2d]) + σ1(W[%2d]) + W[%2d] + W[%2d]' \
                        %(j, '0x' + sum.to_bytes(8, 'big').hex(), j-15, j-2, j-7, j-16))
                
            if (verbose > 2):
                print('[SHA-512]    Finished Preparing Message Schedule')
                print('[SHA-512]    Initializing Local Working Variables')

            # Initialize local state variables
            a = self.H[0]
            b = self.H[1]
            c = self.H[2]
            d = self.H[3]
            e = self.H[4]
            f = self.H[5]
            g = self.H[6]
            h = self.H[7]

            if (verbose > 3):
                print('[SHA-512]        a=%10s b=%10s c=%10s d=%10s e=%10s f=%10s g=%10s h=%10s'%(
                            '0x' + a.to_bytes(8, 'big').hex(), '0x' + b.to_bytes(8, 'big').hex(), 
                            '0x' + c.to_bytes(8, 'big').hex(), '0x' + d.to_bytes(8, 'big').hex(), 
                            '0x' + e.to_bytes(8, 'big').hex(), '0x' + f.to_bytes(8, 'big').hex(), 
                            '0x' + g.to_bytes(8, 'big').hex(), '0x' + h.to_bytes(8, 'big').hex()
                ))

            # At the current iteration, the SHA-512 state variables H0-H7 are read and stored with
            # 8 working variables. Within each block iteration, we iterate through the schedule
            # variables (which are different for each block). Note that in this section, we always
            # use the bitwise addition function.

            for t in range(80):

                # The variables T1 and T2 are computed first. The computation is documented in
                # the official specification. Observe that T1 uses both the t-th schedule
                # variable and the $t-th constant. The Ch function is a choice function. It uses
                # one word, and at each location picks the value from one of the other two words
                # depending on whether the first word has a '1' or '0'.
                T1 = 0
                T1 = self.__bitwise_add__(T1, self.__Sigma1__(e))
                T1 = self.__bitwise_add__(T1, self.__Ch__(e, f, g))
                T1 = self.__bitwise_add__(T1, self.K[t])
                T1 = self.__bitwise_add__(T1, W[t])
                T1 = self.__bitwise_add__(T1, h)

                # The Maj function takes 3 words and for each location returns the most
                # common bit. For example, if in the first bit positions of a, b, c, d,
                # a = 1, b = 0, and c = 1, the return value is 1 in that location, because
                # there are 2 '1's and only 1 '0'.
                T2 = self.__bitwise_add__(self.__Maj__(a, b, c), self.__Sigma0__(a))

                if (verbose > 4):
                    print('[SHA-512]            T1 = %10s  <-  Σ1(e) + Ch(e,f,g) + K[%2d] + W[%2d]'%('0x' + T1.to_bytes(8, 'big').hex(), t, t))
                    print('[SHA-512]            T2 = %10s  <-  Σ0(a) + Maj(a,b,c)'%('0x' + T2.to_bytes(8, 'big').hex()))


                # This effectively discards the last working variable, because
                # no other working variable is assigned the value of h. Also,
                # note that with a few exceptions, 
                h = g
                g = f
                f = e
                
                e = self.__bitwise_add__(d, T1)
                
                d = c
                c = b
                b = a

                a = self.__bitwise_add__(T1, T2)

                if (verbose > 4):
                    print('[SHA-512]            h  = %10s  <-  g'%('0x' + h.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            g  = %10s  <-  f'%('0x' + g.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            f  = %10s  <-  e'%('0x' + f.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            e  = %10s  <-  d + T1'%('0x' + e.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            d  = %10s  <-  c'%('0x' + d.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            c  = %10s  <-  b'%('0x' + c.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            b  = %10s  <-  a'%('0x' + b.to_bytes(8, 'big').hex()))
                    print('[SHA-512]            a  = %10s  <-  T1 + T2'%('0x' + a.to_bytes(8, 'big').hex()))

                if (verbose > 3):
                    print('[SHA-512]        a=%10s b=%10s c=%10s d=%10s e=%10s f=%10s g=%10s h=%10s'%(
                            '0x' + a.to_bytes(8, 'big').hex(), '0x' + b.to_bytes(8, 'big').hex(), 
                            '0x' + c.to_bytes(8, 'big').hex(), '0x' + d.to_bytes(8, 'big').hex(), 
                            '0x' + e.to_bytes(8, 'big').hex(), '0x' + f.to_bytes(8, 'big').hex(), 
                            '0x' + g.to_bytes(8, 'big').hex(), '0x' + h.to_bytes(8, 'big').hex()
                ))

            # Update the state variables for the next iteration.
            self.H[0] = self.__bitwise_add__(self.H[0], a)
            self.H[1] = self.__bitwise_add__(self.H[1], b)
            self.H[2] = self.__bitwise_add__(self.H[2], c)
            self.H[3] = self.__bitwise_add__(self.H[3], d)
            self.H[4] = self.__bitwise_add__(self.H[4], e)
            self.H[5] = self.__bitwise_add__(self.H[5], f)
            self.H[6] = self.__bitwise_add__(self.H[6], g)
            self.H[7] = self.__bitwise_add__(self.H[7], h)

            if (verbose > 1):
                print('[SHA-512]    H[%2d] = %10s %10s %10s %10s %10s %10s %10s %10s'%(
                    i+1, '0x' + self.H[0].to_bytes(8, 'big').hex(), '0x' + self.H[1].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(8, 'big').hex(), '0x' + self.H[3].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(8, 'big').hex(), '0x' + self.H[5].to_bytes(8, 'big').hex(), 
                         '0x' + self.H[6].to_bytes(8, 'big').hex(), '0x' + self.H[7].to_bytes(8, 'big').hex()
                ))

        # At the end of the computation, the output hash value is just self.H,
        # which we updated iteratively.
        output = [item.to_bytes(8, 'big').hex() for item in self.H]
        self.H = self.H0
        hash_value = ''.join(output)

        if (verbose > 0):
            print('[SHA-512] Output Hash: %64s'%(hash_value))

        return hash_value

    # Define functions specifically needed for SHA-512 operations
    def __Ch__(self, x, y, z):
        return (x & y) ^ (~x & z)

    def __Maj__(self, x, y, z):
        return (x & y) ^ (y & z) ^ (x & z)
    
    def __Sigma0__(self, x):
        return self.__rot_right__(x, 28) ^ self.__rot_right__(x, 34) ^ self.__rot_right__(x, 39)

    def __Sigma1__(self, x):
        return self.__rot_right__(x, 14) ^ self.__rot_right__(x, 18) ^ self.__rot_right__(x, 41)

    def __sigma0__(self, x):
        return self.__rot_right__(x, 1) ^ self.__rot_right__(x, 8) ^ self.__right_shift__(x, 7)

    def __sigma1__(self, x):
        return self.__rot_right__(x, 19) ^ self.__rot_right__(x, 61) ^ self.__right_shift__(x, 6)