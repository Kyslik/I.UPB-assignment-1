from kyslikcrypter.encryptor.encryptor import encrypt, decrypt
import argparse
import sys
import timeit

from getpass import getpass
from os.path import exists, splitext

__version__ = "0.2.5"


def main(args=None):
    # arguments initialization for application
    ap = argparse.ArgumentParser(description="Encrypt or decrypt file.")
    ap.add_argument('-d', '--decrypt', action="store_true",
                    help="Decrypt input file")
    ap.add_argument('-f', '--force', action="store_true",
                    help="Overwrite output file if it exists")
    ap.add_argument('infile', help="Input file")
    ap.add_argument('outfile', nargs='?', help="Output file")

    # parse arguments
    args = ap.parse_args(args if args is not None else sys.argv[1:])

    # is outfile specified / if encrypting set name to infile.enc
    if not args.outfile:
        # decrypting
        if args.decrypt:
            args.outfile = splitext(args.infile)[0]
        else:
            args.outfile = args.infile + '.enc'

    if args.outfile == args.infile:
        print("Input and output file must not be the same.")
        return 1

    if exists(args.outfile) and not args.force:
        print("Output file '%s' exists. "
              "Use option -f to override." % args.outfile)
        return 1

    # open infile and outfile
    with open(args.infile, 'rb') as infile, \
            open(args.outfile, 'wb') as outfile:

        if args.decrypt:
            timestartdecrypt = timeit.default_timer()
            # decrypt(infile, outfile, getpass("Enter decryption password: "))
            decrypt(infile, outfile, "abcdefgh")
            timeenddecrypt = timeit.default_timer()
            print("Decrypt time:  %.3f seconds" % (timeenddecrypt - timestartdecrypt))
        else:
            # try:
            #     while True:
            #         passwd = getpass("Enter encryption password: ")
            #         passwd2 = getpass("Verify password: ")
            #
            #         if passwd != passwd2:
            #             print("Password mismatch!")
            #         else:
            #             break
            # except (EOFError, KeyboardInterrupt):
            #     return 1

            timestartencrypt = timeit.default_timer()
            # encrypt(infile, outfile, passwd)
            encrypt(infile, outfile, "abcdefgh")
            timeendencrypt = timeit.default_timer()
            print("Encrypt time:  %.3f seconds" % (timeendencrypt - timestartencrypt))

    return 0

