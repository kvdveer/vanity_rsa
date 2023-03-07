import argparse
import os
import random
import logging

import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

BACKEND = cryptography.hazmat.backends.default_backend()
BASE64_CHARS = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                b"abcdefghijklmnopqrstuvwxyz"
                b"0123456789/+")


logging.basicConfig(level=logging.DEBUG)


def close_prime(n):
    """Find a prime number close to n."""
    if is_prime(n):
        return n  # If already prime - return it as-is.

    if not (n % 2):
        n += 1

    offset = 2
    near_primes = []

    # Find 10 primes near the provided number. This way we eliminate the bias
    # towards primes near large primeless ranges.
    while len(near_primes) < 10:
        if is_prime(n + offset):
            near_primes.append(n + offset)
        if is_prime(n - offset):
            near_primes.append(n - offset)
        offset += 2

    return random.choice(near_primes)


try:
    from gmpy2 import is_prime
except ImportError:
    def is_prime(n, k=10):
        """Implementation of miller rabin prime test"""
        s = 0
        d = n - 1

        while d % 2 == 0:
            d >>= 1
            s += 1

        for _1 in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1:
                return True
            for _2 in range(s - 1):
                if x == n - 1:
                    return True
                x = pow(x, 2, n)
            if x != n - 1:
                return False

        return True


def inject_vanity_ssh(priv_key, vanity):
    """Embed the vanity text in an SSH-format public key

    This key is likely not a valid key, though."""

    logging.debug("Injecting ssh vanity")
    vanity = vanity.encode()
    assert all(c in BASE64_CHARS for c in vanity)

    public_key_repr = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    # Public keys with our chosen exponent all have the same vanity:
    #     'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAg'.  (37 characters)
    # We really can't change this vanity for vanity purposes. The first
    # character after that also encodes the part of the length of N (the key
    # number). After this character, the N actually begins, which is where we
    # can start manipulating the representation.

    public_key_repr = (
        public_key_repr[:38] +
        vanity +
        public_key_repr[38 + len(vanity):]
    )

    # We now have an invalid vanity key. Time to read it back in.
    pub_key = serialization.load_ssh_public_key(public_key_repr, BACKEND)
    return pub_key


def inject_vanity_pem(priv_key, vanity):
    """Embed the vanity text in an PEM-format public key

    This key is likely not a valid key, though."""
    logging.debug("Injecting pem vanity")
    vanity = vanity.encode()
    assert all(c in BASE64_CHARS for c in vanity)

    public_key_repr = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

    lines = public_key_repr.split(b'\n')
    if len(vanity) <= 14:
        # The last 14 characters of the first line encode N
        lines[1] = lines[1][:-len(vanity)] + vanity
    else:
        # The second line is the first line that's entirely encoding N
        lines[2] = vanity + lines[2][len(vanity):]

    public_key_repr = b'\n'.join(lines)
    # print(public_key_repr)

    # We now have an invalid vanity key. Time to read it back in.
    pub_key = serialization.load_pem_public_key(public_key_repr, BACKEND)
    return pub_key


def show_key_ssh(key):
    """Show a private key in SSH format"""

    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    return priv_bytes, pub_bytes


def show_key_pem(key):
    """Show a private key in PEM format"""

    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

    return priv_bytes, pub_bytes


def test_key(key):
    """Encrypt some text with the key to make sure it actually works"""

    logging.debug("Testing the key…")

    # test encryption
    msg = b"This is a test"
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    crypted = key.public_key().encrypt(msg, pad)
    decrypted = key.decrypt(crypted, pad)

    assert msg == decrypted

    # Test verification
    pad = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )

    signature = key.sign(msg, pad, hashes.SHA256())

    key.public_key().verify(
        signature,
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def make_valid_rsa_key(priv_key, pub_key):
    """Generate a valid private key, with N close to the N from pub_key"""

    logging.debug("Generating an RSA key…")

    # Attempt to make the key valid by finding a Q which multiplies with P to
    # form something close to N
    n = pub_key.public_numbers().n
    e = pub_key.public_numbers().e
    p = priv_key.private_numbers().p
    q = close_prime(n // p)

    assert is_prime(e)
    assert is_prime(p)
    assert is_prime(q)

    # Compute D from the new P&Q
    phi = (p - 1) * (q - 1)

    return rsa.RSAPrivateNumbers(
        public_numbers=rsa.RSAPublicNumbers(e, p * q),
        p=p, q=q,
        d=rsa.rsa_crt_iqmp(phi, e),
        dmp1=rsa.rsa_crt_dmp1(e, p),
        dmq1=rsa.rsa_crt_dmp1(e, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
    ).private_key(BACKEND, unsafe_skip_rsa_key_validation=True)


def make_key(vanity, key_length=1024, key_format='ssh'):
    """Generate a valid key with the specified vanity string"""
    # Generate a key to start with. This way we inherit several of the wise
    # choices made by the cryptography authors. (mostly on P selection)
    logging.info(f"Generating {key_format} key of length {key_length}")
    priv_key = rsa.generate_private_key(65537, key_length, BACKEND)

    # Apply some vanity
    if key_format == 'pem':
        pub_key = inject_vanity_pem(priv_key, vanity)
    elif key_format == 'ssh':
        pub_key = inject_vanity_ssh(priv_key, vanity)
    else:
        assert False, 'unknown key type'

    # Generate a valid vanity key
    return make_valid_rsa_key(priv_key, pub_key)


def main():
    parser = argparse.ArgumentParser(
        description=("Generate an RSA key containing arbitrary text in the "
                     "public key."))

    parser.add_argument('vanity', type=str, help="The text to inject")
    parser.add_argument('--key-length', type=int, default=4096,
                        help="The length of the key in bits")
    parser.add_argument('--key-format', choices=['PEM', 'SSH'], default='SSH',
                        help="The format of the key")
    parser.add_argument('--output-file', default='',
                        help="Where to save the private key")
    parser.add_argument('--output-file-public', default='',
                        help="Where to save the public key")
    args = parser.parse_args()
    key_format = args.key_format.lower()

    logging.info("Making a key…")
    # Get the key
    key = make_key(args.vanity, key_length=args.key_length,
                   key_format=key_format)

    logging.info("Testing the key…")
    # Make sure the key actually works
    test_key(key)

    # Encode the key

    if key_format == 'pem':
        logging.info("Encoding the key as pem…")
        priv_key_bytes, pub_key_bytes = show_key_pem(key)
    elif key_format == 'ssh':
        logging.info("Encoding the key as ssh…")
        priv_key_bytes, pub_key_bytes = show_key_ssh(key)
    else:
        assert False, 'unknown key type'

    if args.output_file:
        priv_path = os.path.expanduser(args.output_file)
        if args.output_file_public:
            pub_path = os.path.expanduser(args.output_file_public)
        else:
            pub_path = priv_path + ".pub"

        logging.info(
            f"Writing private and public keys to {priv_path} and {pub_path}")

        with open(priv_path, 'wb') as f:
            f.write(priv_key_bytes)
        os.chmod(priv_path, 0o600)  # Make sure the key is safe
        with open(pub_path, 'wb') as f:
            f.write(pub_key_bytes)
        logging.info("Keys written.")

    else:
        # If the user didn't provide a save path, show the user the result
        print(priv_key_bytes.decode())

    print(pub_key_bytes.decode())
    logging.info('Make sure to add password to your private key!')


if __name__ == '__main__':
    main()
