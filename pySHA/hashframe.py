
class SHA_HashFrame:
    """
    This class is used for implementing the shared functions and public interface
    used by all SHA Hash functions.

    Public Member Functions:
        - update()
        - get_current_input()
        - get_current_output()
        - digest()
        - clear_state

    """
    message = b''
    output = ''

    def update(self, bytes):
        """
        Updates the internal state of the Hasher by
        appending the new message to the existing
        message. After this function is called, the internal
        state is self.message concatenated with bytes.
        Clears the self.output state variable.
        """
        self.message = self.message + bytes
        self.output = ''
        return self.message


    def get_current_input(self):
        """
        Returns the current message held by the hasher's
        internal state.
        """
        return self.message


    def get_current_output(self):
        """
        Returns the current SHA Hash output held by the
        hasher's internal state. If there is no output,
        either because digest() was never called or the output was
        cleared by update() or clear_state(), raises a ValueError
        """

        if self.output == '':
            raise ValueError("Invalid output. Please call digest() before \
                attempting to retrieve the hash output variable.")

        return self.output


    def digest(self):
        """
        Takes the current message held by the hasher's internal
        state and computes the SHA Hash of the message. Stores
        the value in self.output and returns the output value
        """
        blocks = self.__preprocess__(self.message)
        output = self.__hash__(blocks)
        return output


    def clear_state(self):
        """
        Clears the current message held by the hasher's internal
        state
        """
        self.message = b''
        self.output = ''
        return 


    # Logical Primitives used in the SHA Hash family are ~("NOT"), & ("AND")
    # | ("OR"), ^ ("XOR"). Here are the more complicated bit operations

    def __bitwise_add__(self, word1, word2):
        """
        Adds two words bitwise, enabling for wrap around by taking
        only the last self.word_size bits of the sum
        """

        return (word1 + word2) % (1 << self.word_size)


    def __left_shift__(self, word, n):
        """
        Bit shifts the word by n spaces to the left, filling in 
        zeros on the right side. Returns only the last self.word_size bits
        of the result
        """

        return ((word << n) % (1 << self.word_size))


    def __right_shift__(self, word, n):
        """
        Bit shifts the word by n spaces to the right, filling
        in zeros on the left side. Returns only the last self.word_size bits
        of the result
        """

        return ((word >> n) % (1 << self.word_size))


    def __rot_left__(self, word, n):
        """
        Returns the word bit shifted by n spaces to the left, wrapping
        the n leftmost bits to the right (hence, a 'rotation' of the bits).
        """

        return (self.__left_shift__(word, n) | self.__right_shift__(word, self.word_size - n))


    def __rot_right__(self, word, n):
        """
        Returns the word bit shifted by n spaces to the right, wrapping
        the n rightmost bits to the left (hence, a 'rotation' of the bits).
        """

        return (self.__right_shift__(word, n) | self.__left_shift__(word, self.word_size - n))

