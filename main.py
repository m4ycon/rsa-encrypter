from random import randint
from math import gcd
from typing import Dict
from hashlib import sha1, sha3_256
from base64 import b64encode, b64decode
import secrets

class Key():
  k: int
  n: int

  def __init__(self, key: int, n: int):
    self.k = key
    self.n = n

  def __str__(self):
    return f'({self.k}, {self.n})'


TKeysDict = Dict[str, Key]

def xor(bytes1 : bytes, bytes2 : bytes):
    if len(bytes1) != len(bytes2):
        raise ValueError("As strings de bytes devem ter o mesmo comprimento")
    
    return bytes([a ^ b for a, b in zip(bytes1, bytes2)])

def generate_prime() -> int:
  lower_bound, upper_bound = pow(2, 1024), pow(2, 1025) - 1
  prime = 0
  while not is_prime(prime):
    prime = randint(lower_bound, upper_bound)

  return prime


def is_prime(n: int) -> bool:
  # miller-rabin
  # https://www.youtube.com/watch?v=qdylJqXCDGs&ab_channel=Theoretically

  if n == 2 or n == 3:
    return True
  if n <= 1 or n % 2 == 0:
    return False

  k, m = 0, n - 1
  while m % 2 == 0:
    k += 1
    m //= 2

  for _ in range(40):
    a = randint(2, n - 2)
    b = pow(a, m, n)

    if b == 1 or b == n - 1: # inconclusive
      continue

    is_probably_prime = False
    for _ in range(k - 1):
      b = pow(b, 2, n)
      if b == n - 1:
        is_probably_prime = True
        break
    if not is_probably_prime:
      return False
  
  return True


def generate_keys() -> TKeysDict:
  # https://www.youtube.com/watch?v=oOcTVTpUsPQ&ab_channel=EddieWoo
  p, q = generate_prime(), generate_prime()

  n = p * q
  phi = (p - 1) * (q - 1)

  e, d = 2, 2
  while d * e % phi != 1:
    e = randint(2, phi - 1)
    if gcd(e, phi) != 1:
      continue
    try:
      d = pow(e, -1, phi) # modular inverse, extended euclidean algorithm
    except ValueError:
      continue

  d += phi * randint(1e2, 1e6) # add some random number to d, still attending to be modular inverse

  return { 'public': Key(key=e, n=n), 'private': Key(key=d, n=n) }

def mgf1(seed : bytes, mask_len : int, hash_function=sha1):
    hlen = hash_function().digest_size
    if mask_len > (hlen << 32):
      raise ValueError("Máscara muito grande")
    
    masks = b""
    counter = 0
    while len(masks) < mask_len:
        counter_bytes = counter.to_bytes(4, 'big')
        mask = hash_function(seed + counter_bytes).digest()
        masks += mask
        counter += 1

    return masks[:mask_len]

def encode_oaep(plaintext: str, n : int, hash_function=sha1) -> str:
  lhash = hash_function(b'').digest() # bytes da label ""
  hLen = hash_function().digest_size # tamanho do retorno de sha1
  k = (n.bit_length() + 7) // 8 # número de bytes de n (módulo)
  mlen = len(plaintext) # tamanho da mensagem em bytes
  ps = b'\x00' * (k - mlen - 2 * hLen - 2)
  db = lhash + ps + b'\x01' + plaintext.encode('utf-8') # tamanho k - hLen - 1
  seed = secrets.token_bytes(hLen)
  dbMask = mgf1(seed, k - hLen - 1)
  maskedDB = xor(db, dbMask)
  seedMask = mgf1(maskedDB, hLen)
  maskedSeed = xor(seed, seedMask)
  encoded = b'\x00' + maskedSeed + maskedDB
  return b64encode(encoded).decode('utf-8')

def decode_oaep(ciphertext : str, n : int, hash_function=sha1) -> str :
  ciphertextbytes = b64decode(ciphertext)
  hLen = hash_function().digest_size # tamanho do retorno da função de hash
  k = (n.bit_length() + 7) // 8 # número de bytes de p * q
  maskedSeed, maskedDB = ciphertextbytes[1:hLen+1], ciphertextbytes[hLen+1:]
  seedMask = mgf1(maskedDB, hLen)
  seed = xor(maskedSeed, seedMask)
  dbMask = mgf1(seed, k - hLen - 1)
  db =xor(maskedDB, dbMask)
  decoded = db.split(b'\x01', 1)[1]
  return decoded.decode('utf8')

def rsa(input: str, key: Key) -> str:
  inputbytes = b64decode(input)
  k = (key.n.bit_length() + 7) // 8
  int_input = int.from_bytes(inputbytes, "big")
  int_output = pow(int_input, key.k, key.n)
  outputbytes = int_output.to_bytes(k, 'big')
  return b64encode(outputbytes).decode('utf-8')

def cipher(plaintext : str, key: Key) -> bytes:
  encoded = encode_oaep(plaintext, key.n)
  return rsa(encoded, key)

def decipher(ciphertext: str, key: Key) -> str:
  decode = rsa(ciphertext, key)
  return decode_oaep(decode, key.n)

def sign(plaintext : str, key: Key) -> str:
  hash = sha3_256(plaintext.encode('utf-8')).digest()
  return rsa(b64encode(hash).decode('utf-8'), key)

def verify(ciphertext : str, key: Key, signature: str) -> bool:
  msg = decipher(ciphertext, key)
  msghash = sha3_256(msg.encode('utf-8')).digest()
  signaturebytes = b64decode(rsa(signature, key))[-32:] # 32 é o tamanho em bytes do hash sha3_256
  print(f'hash: {msghash}')
  print(f'signature: {signaturebytes}')
  return signaturebytes == msghash

def main():
  keys_pair = generate_keys()
  # print(keys_pair['private'])
  # print(keys_pair['public'])

  plaintext = 'rango brabo demais'
  ciphertext = cipher(plaintext, keys_pair['public'])
  msg = decipher(ciphertext, keys_pair['private'])
  print(f'cipher text: {ciphertext}')
  print(f'msg: {msg}')
  signature = sign(plaintext, keys_pair['public'])
  verified = verify(ciphertext, keys_pair['private'], signature)
  print(f'Verification: {verified}')

main()