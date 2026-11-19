import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sealed = open(sys.argv[1], "rb").read()
key = bytes.fromhex(sys.argv[2])
print("core.enc size =", len(sealed), "key len =", len(key))

magic = sealed[0:4]
version = int.from_bytes(sealed[4:8], "little")
iv = sealed[8:20]
ct_and_tag = sealed[20:]
print("magic =", magic, "version =", version, "iv =", iv.hex(), "ct+tag =", len(ct_and_tag))

try:
    pt = AESGCM(key).decrypt(iv, ct_and_tag, None)  # no AAD
    print("DECRYPT SUCCESS: plaintext =", len(pt), "bytes; first16 =", pt[:16].hex())
except Exception as e:
    print("DECRYPT FAILED:", repr(e))
