from random import getrandbits
from hashlib import sha256

DH_BITS = 2048
DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_GENERATOR = 2


def generate_nonce() -> int:
    """Generate a random 128-bits number to use as a nonce."""
    return getrandbits(128)


def pkey_generation() -> int:
    """Generate a private key, which is a random number less than the prime (p)."""
    return getrandbits(DH_BITS) % (DH_PRIME - 2) + 2


def compute_pubkey(pkey: int) -> int:
    """Compute the public key using modular exponentiation."""
    return pow(DH_GENERATOR, pkey, DH_PRIME)


def compute_secret(pub_key: int, pkey: int) -> bytes:
    """Compute the shared secret and return the hash of it."""
    s = pow(pub_key, pkey, DH_PRIME)
    return sha256(s.to_bytes((s.bit_length() + 7) // 8, "big")).digest()
