from . import hashframe

SHA_HashFrame = hashframe.SHA_HashFrame
class SHA256(SHA_HashFrame):
    """
    Implements the SHA-256 Algorithm
    """

    def __init__(self, verbose=1):
        self.verbose = verbose

        # SHA-256 uses 512-bit blocks with 32-bit (int) word sizes
        self.block_size = 512
        self.word_size = 32
        
        # SHA-256 constants. These are arbitrary in the sense that they are
        # pre-defined in the official specification for the algorithm but 
        # otherwise have no other significant mathematical meaning. These are needed
        # to generate the T1 values in the main hash computation
        constants = """
            428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
            d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
            e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
            983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
            27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
            a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
            19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
            748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
            """

        K = ['0x' + item for item in constants.split()]
        K = [int(item, 0) for item in K]
        self.K = K

        # Initial state variables for SHA-256. Like the constants, these are
        # pre-defined values in the official specification needed to seed the
        # hash values. These are generated from the first 32 bits of the fractional 
        # parts of the square roots of the first 8 prime numbers
        H_init = ["0x6a09e667", "0xbb67ae85", "0x3c6ef372", "0xa54ff53a", "0x510e527f", "0x9b05688c", "0x1f83d9ab", "0x5be0cd19"]
        self.H0 = [int(item, 0) for item in H_init]
        self.H = [int(item, 0) for item in H_init]
        return


    def __preprocess__(self, message):
        """
        Preprocesses the message by paddding it as appropriate to make the total length
        a multiiple of 512 bits and then splitting it into 512-bit blocks.
        """
        verbose = self.verbose

        if (verbose > 1):
            print('[SHA-256] Beginning Preprocessing')

        padded_message_bytes = b''
        if type(message) == bytes:
            nbits = len(message) * 8

            if (verbose > 1):
                print('[SHA-256]    Message Length: %d bits'%(nbits))

            # SHA-256 requires the word blocks to be exactly 512 bits long,
            # in addition to having the message length encoded at the end
            # of the message using 64 bits. Thus, we add 64 to the required
            # bit count for the message length, then round up to 512 bytes,
            # then pad the zeros and the '1' bit
            num_zeros = 448 - nbits - 1
            while num_zeros > self.block_size: num_zeros -= self.block_size
            while num_zeros < 0: num_zeros += self.block_size

            # The number of zeros to pad with is the smallest nonnegative solution
            # to l + 1 + k ≡ 448 mod 512, with l = nbits, the total number of bits in
            # the unpadded message.

            if (verbose > 1):
                print("[SHA-256]    Adding a single '1' bit")

            # The 448 comes from the fact that the last 64 bits in the last
            # padded block are reserved to hold the total length of the message.
            # Thus the maximum. (448 + 64 = 512). Thus, the maximum message size
            # that can be hashed with SHA-256 is 2^64 - 1 bits. Note that after
            # the end of the message, we always add a single '1' bit, which is
            # NOT included in the final 64 bits. The number of zeros is selected
            # such that the last fully padded block is 512 bytes long, of which the
            # last 64 are reserved.

            byte_array = list(message)
            byte_array.append(1 << 7)

            if (verbose > 1): print("[SHA-256]    Padding %d Zeros"%(num_zeros))
            for _ in range(int((num_zeros - 7) / 8)): byte_array.append(0)
            for item in list(nbits.to_bytes(8, 'big')): byte_array.append(item)
            padded_message_bytes = bytes(byte_array)



        nbits = len(padded_message_bytes) * 8
        blocks = []
        nblocks = int(nbits/self.block_size)

        if (verbose > 1):
            print('[SHA-256]    New Input Length: %d bits'%(8 * len(list(byte_array))))
            print('[SHA-256]    Number of %d-bit Blocks: %d'%(self.block_size, nblocks))

        # Splits the padded message into 512-bit blocks
        for i in range(nblocks):
            start = int(i * self.block_size / 8)
            end = int((i + 1) * self.block_size / 8)
            blocks.append( padded_message_bytes[start : end])

        if (verbose > 1): print('[SHA-256] Preprocessing Complete')
        return blocks


    def __hash__(self, blocks):
        """
        The main hash routine. Accepts the blocks generated from the preprocessing
        routing and computes the SHA-256 hash.
        """
        verbose = self.verbose
        N = len(blocks)

        if (verbose > 1):
            print('[SHA-256] Initializing State Variables H0-H7')
            print('[SHA-256]    H[%2d] = %10s %10s %10s %10s %10s %10s %10s %10s'%(
                      0, '0x' + self.H[0].to_bytes(4, 'big').hex(), '0x' + self.H[1].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(4, 'big').hex(), '0x' + self.H[3].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(4, 'big').hex(), '0x' + self.H[5].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[6].to_bytes(4, 'big').hex(), '0x' + self.H[7].to_bytes(4, 'big').hex()
            ))

        # The algorithm must go through every block, so that a change in any bit
        # changes the hash function output.
        for i in range(N):
            
            if (verbose > 2):
                print('[SHA-256] Iterating through Block %d'%(i))

            # Parse the current block
            block = blocks[i]


            if (verbose > 3):
                print('[SHA-256]    Preparing Message Schedule')

            W = []

            # Prepare the message schedule W. The message schedule for SHA-256 consists 
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
                    print('[SHA-256]        W[%2d]=%10s'%(j, '0x' + word.to_bytes(4, 'big').hex()))

            # The last 48 integers in the message schedule are generated iteratively
            # from the first 16. For each new member j of W, it adds W[j-7], W[j-16],
            # and applies two custom functions sigma0 and sigma1 to W[j-15] and W[j-2]. The
            # specific definitions of these are located in the official specification and
            # reproduced below 

            for j in range(16, 64, 1):
                part1 = self.__sigma1__(W[j-2])
                part2 = self.__sigma0__(W[j-15])
                part3 = W[j-16]
                part4 = W[j-7]

                sum = self.__bitwise_add__(part1, part2)
                sum = self.__bitwise_add__(sum, part3)
                sum = self.__bitwise_add__(sum, part4)
                W.append(sum)

                if (verbose > 2):
                    print('[SHA-256]        W[%2d]=%10s       \
                        <- σ0(W[%2d]) + σ1(W[%2d]) + W[%2d] + W[%2d]' \
                        %(j, '0x' + sum.to_bytes(4, 'big').hex(), j-15, j-2, j-7, j-16))
                
            if (verbose > 2):
                print('[SHA-256]    Finished Preparing Message Schedule')
                print('[SHA-256]    Initializing Local Working Variables')

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
                print('[SHA-256]        a=%10s b=%10s c=%10s d=%10s e=%10s f=%10s g=%10s h=%10s'%(
                            '0x' + a.to_bytes(4, 'big').hex(), '0x' + b.to_bytes(4, 'big').hex(), 
                            '0x' + c.to_bytes(4, 'big').hex(), '0x' + d.to_bytes(4, 'big').hex(), 
                            '0x' + e.to_bytes(4, 'big').hex(), '0x' + f.to_bytes(4, 'big').hex(), 
                            '0x' + g.to_bytes(4, 'big').hex(), '0x' + h.to_bytes(4, 'big').hex()
                ))

            # At the current iteration, the SHA-256 state variables H0-H7 are read and stored with
            # 8 working variables. Within each block iteration, we iterate through the schedule
            # variables (which are different for each block). Note that in this section, we always
            # use the bitwise addition function.

            for t in range(64):

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
                    print('[SHA-256]            T1 = %10s  <-  Σ1(e) + Ch(e,f,g) + K[%2d] + W[%2d]'%('0x' + T1.to_bytes(4, 'big').hex(), t, t))
                    print('[SHA-256]            T2 = %10s  <-  Σ0(a) + Maj(a,b,c)'%('0x' + T2.to_bytes(4, 'big').hex()))


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
                    print('[SHA-256]            h  = %10s  <-  g'%('0x' + h.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            g  = %10s  <-  f'%('0x' + g.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            f  = %10s  <-  e'%('0x' + f.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            e  = %10s  <-  d + T1'%('0x' + e.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            d  = %10s  <-  c'%('0x' + d.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            c  = %10s  <-  b'%('0x' + c.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            b  = %10s  <-  a'%('0x' + b.to_bytes(4, 'big').hex()))
                    print('[SHA-256]            a  = %10s  <-  T1 + T2'%('0x' + a.to_bytes(4, 'big').hex()))

                if (verbose > 3):
                    print('[SHA-256]        a=%10s b=%10s c=%10s d=%10s e=%10s f=%10s g=%10s h=%10s'%(
                            '0x' + a.to_bytes(4, 'big').hex(), '0x' + b.to_bytes(4, 'big').hex(), 
                            '0x' + c.to_bytes(4, 'big').hex(), '0x' + d.to_bytes(4, 'big').hex(), 
                            '0x' + e.to_bytes(4, 'big').hex(), '0x' + f.to_bytes(4, 'big').hex(), 
                            '0x' + g.to_bytes(4, 'big').hex(), '0x' + h.to_bytes(4, 'big').hex()
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
                print('[SHA-256]    H[%2d] = %10s %10s %10s %10s %10s %10s %10s %10s'%(
                    i+1, '0x' + self.H[0].to_bytes(4, 'big').hex(), '0x' + self.H[1].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(4, 'big').hex(), '0x' + self.H[3].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(4, 'big').hex(), '0x' + self.H[5].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[6].to_bytes(4, 'big').hex(), '0x' + self.H[7].to_bytes(4, 'big').hex()
                ))

        # At the end of the computation, the output hash value is just self.H,
        # which we updated iteratively.
        output = [item.to_bytes(4, 'big').hex() for item in self.H]
        self.H = self.H0
        hash_value = ''.join(output)

        if (verbose > 0):
            print('[SHA-256] Output Hash: %64s'%(hash_value))

        return hash_value

    # Define functions specifically needed for SHA256 operations
    def __Ch__(self, x, y, z):
        return (x & y) ^ (~x & z)

    def __Maj__(self, x, y, z):
        return (x & y) ^ (y & z) ^ (x & z)
    
    def __Sigma0__(self, x):
        return self.__rot_right__(x, 2) ^ self.__rot_right__(x, 13) ^ self.__rot_right__(x, 22)

    def __Sigma1__(self, x):
        return self.__rot_right__(x, 6) ^ self.__rot_right__(x, 11) ^ self.__rot_right__(x, 25)

    def __sigma0__(self, x):
        return self.__rot_right__(x, 7) ^ self.__rot_right__(x, 18) ^ self.__right_shift__(x, 3)

    def __sigma1__(self, x):
        return self.__rot_right__(x, 17) ^ self.__rot_right__(x, 19) ^ self.__right_shift__(x, 10)