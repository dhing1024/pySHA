from . import hashframe

SHA_HashFrame = hashframe.SHA_HashFrame
class SHA1(SHA_HashFrame):
    """
    Implements the SHA-1 Algorithm
    """

    def __init__(self, verbose=1):
        self.verbose = verbose

        # SHA-1 uses 512-bit blocks with 32-bit (int) word sizes
        self.block_size = 512
        self.word_size = 32
        
        # SHA-1 constants. These are arbitrary in the sense that they are
        # pre-defined in the official specification for the algorithm but 
        # otherwise have no other significant mathematical meaning.
        constants = """
            5a827999 6ed9eba1 8f1bbcdc ca62c1d6
            """

        K = ['0x' + item for item in constants.split()]
        K = [int(item, 0) for item in K]
        self.K = []
        for item in K:
            for _ in range(20):
                self.K.append(item)

        # Initial state variables for SHA-1. Like the constants, these are
        # pre-defined values in the official specification needed to seed the
        # hash values.
        H_init = ["0x67452301", "0xefcdab89", "0x98badcfe", "0x10325476", "0xc3d2e1f0"]
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
            print('[SHA-1] Beginning Preprocessing')

        padded_message_bytes = b''
        if type(message) == bytes:
            nbits = len(message) * 8

            if (verbose > 1):
                print('[SHA-1]    Message Length: %d bits'%(nbits))

            # SHA-1 requires the word blocks to be exactly 512 bits long,
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
                print("[SHA-1]    Adding a single '1' bit")

            # The 448 comes from the fact that the last 64 bits in the last
            # padded block are reserved to hold the total length of the message.
            # Thus the maximum. (448 + 64 = 512). Thus, the maximum message size
            # that can be hashed with SHA-1 is 2^64 - 1 bits. Note that after
            # the end of the message, we always add a single '1' bit, which is
            # NOT included in the final 64 bits. The number of zeros is selected
            # such that the last fully padded block is 512 bytes long, of which the
            # last 64 are reserved.

            byte_array = list(message)
            byte_array.append(1 << 7)

            if (verbose > 1): print("[SHA-1]    Padding %d Zeros"%(num_zeros))
            for _ in range(int((num_zeros - 7) / 8)): byte_array.append(0)
            for item in list(nbits.to_bytes(8, 'big')): byte_array.append(item)
            padded_message_bytes = bytes(byte_array)



        nbits = len(padded_message_bytes) * 8
        blocks = []
        nblocks = int(nbits/self.block_size)

        if (verbose > 1):
            print('[SHA-1]    New Input Length: %d bits'%(8 * len(list(byte_array))))
            print('[SHA-1]    Number of %d-bit Blocks: %d'%(self.block_size, nblocks))

        # Splits the padded message into 512-bit blocks
        for i in range(nblocks):
            start = int(i * self.block_size / 8)
            end = int((i + 1) * self.block_size / 8)
            blocks.append( padded_message_bytes[start : end])

        if (verbose > 1): print('[SHA-1] Preprocessing Complete')
        return blocks


    def __hash__(self, blocks):
        """
        The main hash routine. Accepts the blocks generated from the preprocessing
        routing and computes the SHA-1 hash.
        """
        verbose = self.verbose
        N = len(blocks)

        if (verbose > 1):
            print('[SHA-1] Initializing State Variables H0-H4')
            print('[SHA-1]    H[%2d] = %10s %10s %10s %10s %10s'%(
                      0, '0x' + self.H[0].to_bytes(4, 'big').hex(), '0x' + self.H[1].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(4, 'big').hex(), '0x' + self.H[3].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(4, 'big').hex()
            ))

        # The algorithm must go through every block, so that a change in any bit
        # changes the hash function output.
        for i in range(N):
            
            if (verbose > 2):
                print('[SHA-1] Iterating through Block %d'%(i))

            # Parse the current block
            block = blocks[i]


            if (verbose > 3):
                print('[SHA-1]    Preparing Message Schedule')

            W = []

            # Prepare the message schedule W. The message schedule for SHA-1 consists 
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
                    print('[SHA-1]        W[%2d]=%10s'%(j, '0x' + word.to_bytes(4, 'big').hex()))

            # The last 64 integers in the message schedule are generated iteratively
            # from the first 16. For each new member j of W, it XORs W[j-3], W[j-8], W[j-14], 
            # and W[j-16]. Then it rotates left by one bit. The
            # specific definitions of these are located in the official specification and
            # reproduced below 

            for j in range(16, 80, 1):
                W_j = self.__rot_left__(W[j-3] ^ W[j-8] ^ W[j-14] ^ W [j-16], 1)
                W.append(W_j)

                if (verbose > 2):
                    print('[SHA-1]        W[%2d]=%10s       \
                        <- Rot_Left(W[%2d] xor W[%2d] xor W[%2d] xor W[%2d], 1)' \
                        %(j, '0x' + W_j.to_bytes(4, 'big').hex(), j-3, j-8, j-14, j-16))
                
            if (verbose > 2):
                print('[SHA-1]    Finished Preparing Message Schedule')
                print('[SHA-1]    Initializing Local Working Variables')

            # Initialize local state variables
            a = self.H[0]
            b = self.H[1]
            c = self.H[2]
            d = self.H[3]
            e = self.H[4]

            if (verbose > 3):
                print('[SHA-1]        a=%10s b=%10s c=%10s d=%10s e=%10s'%(
                            '0x' + a.to_bytes(4, 'big').hex(), '0x' + b.to_bytes(4, 'big').hex(), 
                            '0x' + c.to_bytes(4, 'big').hex(), '0x' + d.to_bytes(4, 'big').hex(), 
                            '0x' + e.to_bytes(4, 'big').hex()
                ))

            # At the current iteration, the SHA-1 state variables H0-H4 are read and stored with
            # 5 working variables. Within each block iteration, we iterate through the schedule
            # variables (which are different for each block). Note that in this section, we always
            # use the bitwise addition function.

            for t in range(80):

                # The variables T is computed first. The computation is documented in
                # the official specification.
                T = self.__rot_left__(a, 5)
                T = self.__bitwise_add__(T, self.__f_t__(t, b, c, d))
                T = self.__bitwise_add__(T, e)
                T = self.__bitwise_add__(T, self.K[t])
                T = self.__bitwise_add__(T, W[t])

                if (verbose > 4):
                   print('[SHA-1]            T = %10s  <-  f_%2d(b, c, d) + e + K[%2d] + W[%2d]'%('0x' + T.to_bytes(4, 'big').hex(), t, t, t))

                e = d
                d = c
                c = self.__rot_left__(b, 30)
                b = a
                a = T

                if (verbose > 4):
                    print('[SHA-1]            e  = %10s  <-  d'%('0x' + e.to_bytes(4, 'big').hex()))
                    print('[SHA-1]            d  = %10s  <-  c'%('0x' + d.to_bytes(4, 'big').hex()))
                    print('[SHA-1]            c  = %10s  <-  Rot_Left(b, 30)'%('0x' + c.to_bytes(4, 'big').hex()))
                    print('[SHA-1]            b  = %10s  <-  a'%('0x' + b.to_bytes(4, 'big').hex()))
                    print('[SHA-1]            a  = %10s  <-  T'%('0x' + a.to_bytes(4, 'big').hex()))

                if (verbose > 3):
                    print('[SHA-1]        a=%10s b=%10s c=%10s d=%10s e=%10s'%(
                            '0x' + a.to_bytes(4, 'big').hex(), '0x' + b.to_bytes(4, 'big').hex(), 
                            '0x' + c.to_bytes(4, 'big').hex(), '0x' + d.to_bytes(4, 'big').hex(), 
                            '0x' + e.to_bytes(4, 'big').hex()
                ))

            # Update the state variables for the next iteration.
            self.H[0] = self.__bitwise_add__(self.H[0], a)
            self.H[1] = self.__bitwise_add__(self.H[1], b)
            self.H[2] = self.__bitwise_add__(self.H[2], c)
            self.H[3] = self.__bitwise_add__(self.H[3], d)
            self.H[4] = self.__bitwise_add__(self.H[4], e)

            if (verbose > 1):
                print('[SHA-1]    H[%2d] = %10s %10s %10s %10s %10s'%(
                    i+1, '0x' + self.H[0].to_bytes(4, 'big').hex(), '0x' + self.H[1].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[2].to_bytes(4, 'big').hex(), '0x' + self.H[3].to_bytes(4, 'big').hex(), 
                         '0x' + self.H[4].to_bytes(4, 'big').hex()
                ))

        # At the end of the computation, the output hash value is just self.H,
        # which we updated iteratively.
        output = [item.to_bytes(4, 'big').hex() for item in self.H]
        self.H = self.H0
        hash_value = ''.join(output)

        if (verbose > 0):
            print('[SHA-1] Output Hash: %40s'%(hash_value))

        return hash_value

    # Define functions specifically needed for SHA1 operations

    def __f_t__(self, t, x, y, z):
        if t >= 0 and t <= 19:
            return (x & y) ^ (~x & z)
        elif t >= 20 and t <= 39:
            return x ^ y ^ z
        elif t >= 40 and t <= 59:
            return (x & y) ^ (y & z) ^ (x & z)
        elif t >= 60 and t <= 79:
            return x ^ y ^ z
