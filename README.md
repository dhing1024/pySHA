# pySHA

**Author**: Dominick Hing, dominick.hing1024@gmail.com


This repository contains an implementation of the following functions: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256,
along with a program that uses these implementations to hash various inputs.

**Disclaimer:** this repository is intended to demonstrate the SHA algorithms for educational purposes only. It is not intended for use in production deployments.
For production deployments, use the built in `hashlib` library or the PyCryptodome library. The [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)
library can be installed using `pip install pycryptodome`. Rather, these implementations are intended to serve as an educational resource to demonstrate how these
functions work.

The repository comes with a main `sha.py` program which accepts inputs and returns the hash value. It also includes a file `shatester.py` which can be used to
verify the accuracy of the provided implementations.


## Files ##

This repository is structured such that all of the SHA algorithms can share as much functionality as possible. This is mainly done in `hashframe.py` and
the individual algorithms are implemented in separate files under the `pySHA` directory. The main program to be run is `sha.py` and the testing program is
`shatester.py`

- `sha.py`: the main program used to run the SHA implementations
- `shatester.py`: the testing program used to verify that the SHA implementations are correct
- `pySHA`: folder containing the SHA implementations
  - `__init__.py`: allows for simplified naming conventions by the importing python file
  - `hashframe.py`: provides a skeleton used by the individual hash functions that contains various shared functionality
  - `sha1.py`: implements that SHA-1 class
  - `sha224.py`: implements the SHA-224 class
  - `sha256.py`: implements the SHA-256 class
  - `sha384.py`: implements the SHA-384 class
  - `sha512_224.py`: implements the SHA-512/224 class
  - `sha512_256.py`: implements the SHA-512/256 class
  - `sha512.py`: implements the SHA-512 class
  
  
## Functionality ##

To run the main SHA program, run `python3 sha.py` along with additional arguments

- `-a` or `--algorithm`: accepts values of `1`, `224`, `256`, `384`, `512`, `512/224`, `512/256`
- `-v` or `--verbosity`: accepts an integer from `0` to `5`, with `0` being the least verbose and `5` being the most verbose. Defaults to `0`. The higher
the verbosity, the more intermediate steps are displayed in the terminal.

Exactly one of the following must be provided:

- `-t` or `--text`: provide the text to be hashed directly through the command line
- `-f` or `--file`: provide a filename to be hashed directly through the command line. The file's contents will be hashed. This
is equivalent to using the `shasum` command directly in the terminal with a file input.
- `--test`: hash the string `abc`

**Examples:**

- To hash the file `index.html` using SHA-256 with verbosity 2, run `python3 sha.py -v 2 -a 256 --file index.html` in the command line.
- To hash the string 'foo' using SHA-1 with verbosity 0, run `python3 sha.py -a 1 --t foo`


## Testing ##

To run the testing suite, you must install [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html). The
easiest way to do so is using pip: `pip install pycryptodome`. This is also provided in the `requirements.txt` file, so 
you may also use `pip install -r requirements.txt`

Then run `python3 shatester.py`. This will run the testing suite to verify that all SHA implementations are correct
