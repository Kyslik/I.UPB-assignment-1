from struct import pack, unpack
from os import urandom
from progress.bar import Bar
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512
from pbkdf2 import PBKDF2

# delimiter
SALT_MARKER = b'$]*'

# iterations for PBKDF2
ITERATIONS = 1000

MULTIPLIER = 1024

__all__ = ('encrypt', 'decrypt')


def encrypt(infile, outfile, password, args={}, key_size=32, salt_marker=SALT_MARKER,
            kdf_iterations=ITERATIONS, hashmod=SHA256):
    """
    Encrypt infile and write it to outfile using password to generate key.
    The encryption algorithm used is symmetric AES in cipher-block chaining
    (CBC) mode.
    Use SHA512 for integrity check.
    :param infile:
    :param outfile:
    :param password:
    :param key_size:
    :param salt_marker:
    :param kdf_iterations:
    :param hashmod:
    :return:
    """
    # check that salt_maker is between 1 and 6 bytes long (and is in fact byte type)
    if not 1 <= len(salt_marker) <= 6:
        raise ValueError('The salt_marker must be one to six bytes long.')
    elif not isinstance(salt_marker, bytes):
        raise TypeError('salt_marker must be a bytes instance.')

    # check for max iterations
    if kdf_iterations >= 65536:
        raise ValueError('kdf_iterations must be <= 65535.')

    bs = AES.block_size

    # create header data consisting of kdf_iterations
    header = salt_marker + pack('>H', kdf_iterations) + salt_marker

    # generate (pseudo) random salt
    salt = urandom(bs - len(header))

    # use password key based derivation algorithm to generate hash based on pass + salt
    kdf = PBKDF2(password, salt, min(kdf_iterations, 65535), hashmod)
    key = kdf.read(key_size)

    # generate (pseudo) random IV
    iv = urandom(bs)

    # create cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # integrity check - get hash of file and encrypt it
    cryptedfilehash = cipher.encrypt(hashfile(infile))

    # write encrypted filehash in outfile 64b
    outfile.write(cryptedfilehash)

    # write header and salt 16b
    outfile.write(header + salt)

    # write iv 16b
    outfile.write(iv)

    if not args["quiet"] and args["progress_bar"]:
        encryptbar = Bar('Encrypting', max=ceil(filesize(infile) / (MULTIPLIER * bs)))

    pads = False
    # read file by MULTIPLIER * AES.block_size
    for chunk in iter(lambda: infile.read(MULTIPLIER * bs), b''):
        # is this last chunk || is chunk less than MULTIPLIER*bs
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += (padding_length * chr(padding_length)).encode()
            pads = True

        # write encrypted chunks in file
        outfile.write(cipher.encrypt(chunk))
        encryptbar.next() if 'encryptbar' in locals() else None

    if not pads:
            outfile.write(cipher.encrypt((bs * chr(bs)).encode()))

    encryptbar.finish() if 'encryptbar' in locals() else None

    return None


def decrypt(infile, outfile, password, args={}, key_size=32, salt_marker=SALT_MARKER,
            hashmod=SHA256):
    """
    Decrypt infile and write it to outfile using password to derive key.
    See `encrypt` for documentation of the encryption algorithm and parameters.
    :param infile:
    :param outfile:
    :param password:
    :param key_size:
    :param salt_marker:
    :param hashmod:
    :return:
    """
    # read first 64 bytes of file and get encrypted file hash
    cryptedfilehash = infile.read(SHA512.digest_size)

    # calculate header length
    mlen = len(salt_marker)
    hlen = mlen * 2 + 2

    # check that salt_maker is between 1 and 6 bytes long (and is in fact byte type)
    if not 1 <= mlen <= 6:
        raise ValueError('The salt_marker must be one to six bytes long.')
    elif not isinstance(salt_marker, bytes):
        raise TypeError('salt_marker must be a bytes instance.')

    bs = AES.block_size

    # read salt from infile (which is marked by salt_marker)
    salt = infile.read(bs)

    # extract salt, extract iterations number
    if salt[:mlen] == salt_marker and salt[mlen + 2:hlen] == salt_marker:
        kdf_iterations = unpack('>H', salt[mlen:mlen + 2])[0]
        salt = salt[hlen:]
    else:
        kdf_iterations = ITERATIONS

    # raise exception because somehow iterations is larger than 65535
    if kdf_iterations >= 65536:
        raise ValueError('kdf_iterations must be <= 65535.')

    # read iv from file
    iv = infile.read(bs)

    # use password key based derivation algorithm to generate hash based on pass + salt
    kdf = PBKDF2(password, salt, kdf_iterations, hashmod)
    key = kdf.read(key_size)

    # create cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decypher file hash (stored in infile)
    decryptedfilehash = cipher.decrypt(cryptedfilehash)

    # create SHA512 object so when we iterate chunk by chunk we update hash
    filehash = SHA512.new()

    if not args["quiet"] and args["progress_bar"]:
        encryptbar = Bar('Encrypting', max=ceil((filesize(infile) - 96) / (MULTIPLIER * bs)))

    for chunk in iter(lambda: infile.read(MULTIPLIER * bs), b''):
        try:
            curr_chunk = cipher.decrypt(chunk)
        except ValueError:
            break # we break instead of showing error
        if len(curr_chunk) < MULTIPLIER * bs:
            curr_chunk = unpad(bs, curr_chunk)
        filehash.update(curr_chunk)
        outfile.write(curr_chunk)
        encryptbar.next() if 'encryptbar' in locals() else None
    encryptbar.finish() if 'encryptbar' in locals() else None

    print("Integrity check SHA512: {0}".format(("OK" if filehash.digest() == decryptedfilehash else "FAIL")))

    return None


def unpad(bs, chunk):
    padlen = chunk[-1]

    if isinstance(padlen, str):
        padlen = ord(padlen)
        padding = padlen * chr(padlen)
    else:
        padding = (padlen * chr(chunk[-1])).encode()

    if padlen < 1 or padlen > bs:
        return chunk
        # raise ValueError("Bad decrypt pad (%d)" % padlen)

    # all the pad-bytes must be the same
    if chunk[-padlen:] != padding:
        return chunk
        # raise ValueError("Bad decrypt")
    chunk = chunk[:-padlen]
    return chunk


def hashfile(file, blocksize=2 ** 13):
    """
    Calculate hash of filestream and return pointer back to its original position.
    :param file:
    :param blocksize:
    :return:
    """

    # get current position
    pos = file.tell()
    buffer = file.read(blocksize)
    hasher = SHA512.new()

    while len(buffer) > 0:
        hasher.update(buffer)
        buffer = file.read(blocksize)
    file.seek(pos)
    return hasher.digest()


def filesize(file):
    """
    Returns a file size of opened file.
    :param file:
    :return:
    """
    pos = file.tell()  # Save the current position
    file.seek(0, 2)  # Seek to the end of the file
    length = file.tell()  # The current position is the length
    file.seek(pos)  # Return to the saved position
    return length


def ceil(n):
    res = int(n)
    return res if res == n or n < 0 else res+1


def floor(n):
    res = int(n)
    return res if res == n or n >= 0 else res-1