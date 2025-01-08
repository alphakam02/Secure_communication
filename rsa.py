from random import getrandbits
from sympy import isprime, mod_inverse
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from hashlib import sha256


def generate_prime(bits=1024) -> int:
    """Generate a prime number with the given number of bits."""
    while True:
        candidate = getrandbits(bits)
        # Ensure the candidate is odd and large enough
        candidate |= (1 << bits - 1) | 1
        if isprime(candidate):
            return candidate


def generate_pkey() -> crypto.PKey:
    """Generate RSA public and private keys."""
    # Generate two large primes, p and q
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi_n)
    # Convert the keys to an OpenSSL object
    keys = RSA.construct((n, e, d, p, q))
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, keys.export_key())
    return pkey


def generate_cert(pkey: crypto.PKey) -> crypto.X509:
    """Generate a self-signed certificate using the private key"""
    # Create a self-signed certificate
    cert = crypto.X509()
    # Set the subject of the certificate
    name = cert.get_subject()
    name.C = "FR"
    name.ST = "Brittany"
    name.L = "Rennes"
    name.O = "University of Rennes 1"
    name.OU = "CyberSchool"
    name.CN = "localhost"
    # Last configurations for the certificate
    cert.set_issuer(name)
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 60)
    cert.set_pubkey(pkey)
    # Sign the certificate and return
    cert.sign(pkey, "sha256")
    return cert


def parse_cert(data: str) -> crypto.X509:
    """Parse the certificate from the given data."""
    return crypto.load_certificate(crypto.FILETYPE_PEM, data.encode())


def encode_cert(cert: crypto.X509) -> str:
    """Encode the certificate to a string to be json compatible."""
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()


def verify_cert(cert: crypto.X509) -> bool:
    """Verify the self-signed certificate."""
    if cert.has_expired():
        return False
    store = crypto.X509Store()
    store.add_cert(cert)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
        return True
    except crypto.X509StoreContextError as e:
        return False


def sign(msg: str, pkey: crypto.PKey) -> int:
    """Sign a message with RSA using the private key."""
    hashed = int(sha256(msg.encode()).hexdigest(), 16)
    numbers = pkey.to_cryptography_key().private_numbers()
    return pow(hashed, numbers.d, numbers.public_numbers.n)


def verify_sign(msg: str, sign: int, cert: crypto.X509) -> bool:
    """Verify a message signature with RSA using the public key."""
    msg_hash = int(sha256(msg.encode()).hexdigest(), 16)
    numbers = cert.get_pubkey().to_cryptography_key().public_numbers()
    sign_hash = pow(sign, numbers.e, numbers.n)
    return sign_hash == msg_hash
