import argparse
import psutil
from sys import argv, exit, stdout
from timeit import default_timer
from kyslikcrypter.encryptor.encryptor import encrypt, decrypt
from getpass import getpass, getuser
from os.path import exists, splitext
from os import urandom
from Crypto.Hash import SHA256



__version__ = "0.4.2"


def main(args=None):
    # arguments initialization for application
    ap = argparse.ArgumentParser(description="Encrypt or decrypt file.")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="display no output (except when -gp flag is set)")
    ap.add_argument("-d", "--decrypt", action="store_true",
                    help="decrypt input file")
    ap.add_argument("-f", "--force", action="store_true",
                    help="overwrite output file if it exists")
    ap.add_argument("-ch", "--check-sum", action="store_true",
                    help="display file checksum(s) (SHA512)")
    ap.add_argument("-pb", "--progress-bar", action="store_true",
                    help="display progress bar")
    ap.add_argument("-gp", "--generate-pass", metavar="PASS LENGTH", const=8, default=None, type=int, action="store",
                    nargs="?",
                    help="generates and displays pass phrase used to encrypt file")
    ap.add_argument("-i", "--infile", required=True, help="input file")
    ap.add_argument("-o", "--outfile", nargs="?", help="output file")

    # parse arguments
    args = ap.parse_args(args if args is not None else argv[1:])

    checkfiles(args)

    gen_pass = generatepass(args)

    # open infile and outfile
    with open(args.infile, "rb") as infile, \
            open(args.outfile, "wb") as outfile:

        if args.decrypt:
            passwd = getpass("Enter decryption password: ")
            timestartdecrypt = default_timer()
            decrypt(infile, outfile, passwd)
            timeenddecrypt = default_timer()
            print("Decrypt time:  %.3f seconds." % (timeenddecrypt - timestartdecrypt))
        else:
            if gen_pass is None:
                try:
                    while True:
                        passwd = getpass("Enter encryption password: ")
                        if passwd != getpass("Verify password: "):
                            print("Password mismatch! Please try again. \n Or ctrl+d to exit.")
                        else:
                            break
                except (EOFError, KeyboardInterrupt):
                    return 1
            else:
                passwd = gen_pass

            timestartencrypt = default_timer()
            encrypt(infile, outfile, passwd)
            timeendencrypt = default_timer()
            print("Encrypt time:  %.3f seconds." % (timeendencrypt - timestartencrypt))

    process = psutil.Process()

    print("RAM usage: {0} MB".format(process.memory_info()[0] / float(2 ** 20)))
    return 0


def checkfiles(args):

    # is outfile specified / if encrypting set name to infile.enc
    if not args.outfile:
        # decrypting option selected
        args.outfile = splitext(args.infile)[0] if args.decrypt else args.infile + ".enc"

    if args.outfile == args.infile:
        print("Input and output file must not be the same.")
        exit(1)

    if exists(args.outfile) and not args.force:
        print("Output file '{0}' exists. "
              "Use option -f to override.".format(args.outfile))
        if query_yes_no("Do you want to continue anyway?", "no") is False:
            exit(1)

    if not exists(args.infile):
        print("Input file {0} does not exist.".format(args.infile))
        exit(1)


def generatepass(args):
    # generate pass phrase using SHA512(SALT + username)
    if args.generate_pass is not None and not args.decrypt:
        pass_length = abs(min(args.generate_pass, 64))
        gen_pass = SHA256.new(urandom(32) + str.encode(getuser())).hexdigest()[:pass_length]
        print("Generated pass phrase with length {0} (on new line): \n{1} \n".format(int(pass_length), gen_pass))
        return gen_pass
    return None


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            stdout.write("Please respond with 'yes' or 'no' "
                         "(or 'y' or 'n').\n")
