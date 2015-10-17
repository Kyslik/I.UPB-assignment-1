"""bootstrap.bootstrap: provides entry point main()."""
import sys

__version__ = "0.0.1"


def main():
    print("Executing kyslikcrypter version %s." % __version__)
    print("List of argument strings: %s" % sys.argv[1:])

