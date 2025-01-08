from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


def protect(msg: bytes, skey: bytes, header: bytes) -> dict:
    """Encrypt a message using AES-GCM.
    The header is used to store the session id and sequence number."""
    nonce = get_random_bytes(16)
    encryptor = AES.new(skey, AES.MODE_GCM, nonce=nonce)
    encryptor.update(header)
    cipher, tag = encryptor.encrypt_and_digest(msg)
    return dict(
        cipher=b64encode(cipher).decode(),
        tag=b64encode(tag).decode(),
        nonce=b64encode(nonce).decode(),
        header=b64encode(header).decode(),
    )


def unprotect(data: dict, skey: bytes) -> bytes:
    """Decrypt a message using AES-GCM.
    Proceed for the verification of session id and sequence number."""
    nonce = b64decode(data["nonce"])
    cipher = b64decode(data["cipher"])
    tag = b64decode(data["tag"])
    header = b64decode(data["header"])
    decryptor = AES.new(skey, AES.MODE_GCM, nonce=nonce)
    decryptor.update(header)
    return decryptor.decrypt_and_verify(cipher, tag)
