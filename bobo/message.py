import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA512, Hash
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

def read_header(f):
    return json.loads(f.read(int(f.read(int(f.read(1))))))

def file_hash(f):
    ctx = SHA512()
    hasher = Hash(ctx, default_backend())
    while True:
        data = f.read(1024)
        if not data:
            break
        hasher.update(data)
    digest = hasher.finalize()
    alg = ECDSA(Prehashed(ctx))
    return digest, alg

def read_signed(f):
    header = read_header(f)
    pos = f.tell()
    pkey = b64decode(header["key"])
    public_key = load_der_public_key(pkey, default_backend())
    digest, alg = file_hash(f)
    public_key.verify(b64decode(header["sig"]), digest, alg)
    f.seek(pos)
    return read_message(f) + (pkey,)

def read_message(f):
    t = f.read(1)

    if t == b'S':
        return read_signed(f)

    assert t == b'P'
    header = read_header(f)
    pos = f.tell()
    return (header, pos)

def format_header(header):
    header = json.dumps(header, sort_keys=True, separators=(',',':')) + '\n'
    size = str(len(header))
    return (str(len(size)) + size + header).encode()

def sign_message(private_key, data):
    signature = private_key.sign(data, ECDSA(SHA512()))

    public_key = encode_public_key(private_key.public_key())

    header = {"key": b64encode(public_key).decode(), 'sig': b64encode(signature).decode()}
    return b'S' + format_header(header) + data

def format_message(header, data=b''):
    return b'P' + format_header(header) + data

def encode_public_key(public_key):
    return public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo)
