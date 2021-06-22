import argparse
from pySHA import SHA1
from pySHA import SHA224
from pySHA import SHA256
from pySHA import SHA384
from pySHA import SHA512
from pySHA import SHA512_224
from pySHA import SHA512_256


def parse_args():
    parser = argparse.ArgumentParser(description='Compute the SHA Hash of an input.')
    parser.add_argument('--algorithm', '-a', 
                        type=str, 
                        choices=['1', '224', '256', '384', '512', '512224', '512256'], 
                        help='The specific SHA hash function. Currently only supports SHA-1 and SHA-256', 
                        required=True)
    parser.add_argument('--verbosity', '-v', 
                        type=int, 
                        choices=[0,1,2,3,4,5],
                        default=0)

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--text', '-t',
                        type=str, 
                        default=None,
                        help='Calculates the hash using the provided text at the command line')
    input_group.add_argument('--file', '-f',
                        type=str,
                        default=None,
                        help='Calculates the hash using the provided input file')
    input_group.add_argument('--test', 
                        action='store_true',
                        help='Calculates the hash using the test message `abc`')
    
    args = parser.parse_args()
    return args


if __name__ == '__main__':

    # The default argparse value for the verbosity is 0
    args = parse_args()
    if (args.verbosity > 0):
        print()

    # Generate a hasher depending on the specified input
    if (args.algorithm == '1'):
        hasher = SHA1(verbose=args.verbosity)
    elif (args.algorithm == '224'):
        hasher = SHA224(verbose=args.verbosity)
    elif (args.algorithm == '256'):
        hasher = SHA256(verbose=args.verbosity)
    elif (args.algorithm == '384'):
        hasher = SHA384(verbose=args.verbosity)
    elif (args.algorithm == '512'):
        hasher = SHA512(verbose=args.verbosity)
    elif (args.algorithm == '512224'):
        hasher = SHA512_224(verbose=args.verbosity)
    elif (args.algorithm == '512256'):
        hasher = SHA512_256(verbose=args.verbosity)

    # Handle case where the --test flag is set
    if (args.test):
        message = 'abc'
        hasher.update(message.encode('utf-8'))

    # Handle case where the --file flag is set
    elif (args.file):
        f = open(args.file, 'rb')
        while True:
            line = f.readline()
            if len(line) == 0:
                break
            hasher.update(line)

    # Handle case where the --text flag is set
    elif (args.text):
        message = args.text
        hasher.update(message.encode('utf-8'))


    # This executes the hash function calculation and
    # displays the output in the terminal, provided that
    # the hasher's verbosity is 1 or above. The default action
    # is that verbosity is set to 0 and the hash value is printed
    # not by the hasher, but in this function below.
    hash_value = hasher.digest()

    if (args.verbosity == 0):
        print(hash_value)

    if (args.verbosity > 0):
        print()