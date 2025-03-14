import base64
from hashlib import sha256
from Crypto.Hash import RIPEMD160
from coincurve import PrivateKey, PublicKey
import base58

def evrmore_message_hash(message: str) -> bytes:
    prefix = b"Evrmore Signed Message:\n"
    def varint(n):
        if n < 253:
            return bytes([n])
        elif n < 0x10000:
            return b'\xfd' + n.to_bytes(2, 'little')
        elif n < 0x100000000:
            return b'\xfe' + n.to_bytes(4, 'little')
        else:
            return b'\xff' + n.to_bytes(8, 'little')

    prefix_bytes = varint(len(prefix)) + prefix
    message_bytes = varint(len(message)) + message.encode('utf-8')
    to_hash = prefix_bytes + message_bytes
    return sha256(sha256(to_hash).digest()).digest()

def wif_to_privkey(wif: str) -> bytes:
    decoded = base58.b58decode_check(wif)
    if decoded[0] != 0x80:
        raise ValueError("Invalid WIF prefix")
    return decoded[1:33]

def pubkey_to_address(pubkey: bytes) -> str:
    sha = sha256(pubkey).digest()
    ripe = RIPEMD160.new(sha).digest()
    versioned = b'\x21' + ripe  # Evrmore mainnet P2PKH prefix 0x21
    checksum = sha256(sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()

def sign_message(message: str, wif_privkey: str) -> str:
    privkey = PrivateKey(wif_to_privkey(wif_privkey))
    msg_hash = evrmore_message_hash(message)
    
    signature_full = privkey.sign_recoverable(msg_hash, hasher=None)
    
    # signature_full[-1] is the recid, signature_full[:-1] is r+s
    signature, recid = signature_full[:64], signature_full[64]
    
    # Correct header byte calculation:
    header_byte = 27 + recid + 4  # 4 is added because we're using compressed keys
    
    sig_compact = bytes([header_byte]) + signature
    return base64.b64encode(sig_compact).decode()


def verify_message(address: str, signature_b64: str, message: str) -> bool:
    sig_compact = base64.b64decode(signature_b64)
    if len(sig_compact) != 65:
        print("Invalid signature length.")
        return False
    
    header = sig_compact[0]
    
    if header < 27 or header > 34:
        print("Invalid header byte.")
        return False
    
    recid = (header - 27) & 3
    compressed = ((header - 27) & 4) != 0
    
    msg_hash = evrmore_message_hash(message)
    
    try:
        pubkey = PublicKey.from_signature_and_message(sig_compact[1:] + bytes([recid]), msg_hash, hasher=None)
        pubkey_bytes = pubkey.format(compressed=compressed)
        derived_address = pubkey_to_address(pubkey_bytes)
        return derived_address == address
    except Exception as e:
        print(f"Verification error: {e}")
        return False




# Example usage:
if __name__ == '__main__':
    message = "Hello Evrmore"
    wif_privkey = "KwS1DUSPM5vGQ1b5XCd1BaQrKyDc2sfKr6eGFwdQrmX1MhkYor83"

    signature = sign_message(message, wif_privkey)
    print(f"Signature: {signature}")

    # Derive address from private key to test verification
    privkey = PrivateKey(wif_to_privkey(wif_privkey))
    address = pubkey_to_address(privkey.public_key.format(compressed=True))

    print(f"Address: {address}")

    verified = verify_message(address, signature, message)
    print(f"Verified: {verified}")