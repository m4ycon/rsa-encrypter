from random import randint
from math import gcd
from typing import Dict, Tuple

class Key():
  k: int
  n: int

  def __init__(self, key: int, n: int):
    self.k = key
    self.n = n

  def __str__(self):
    return f'({self.k}, {self.n})'


TKeysDict = Dict[str, Key]


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

def oaep(plaintext: str) -> str:
  return plaintext

def crypt(plaintext: str, key: Key) -> str:
  paddedtext = oaep(plaintext)
  ciphertext = ''
  for i in paddedtext:
    cipher_i = pow(ord(i), key.k, key.n)
    print(hex(cipher_i))
    ciphertext += chr(cipher_i)
  return ciphertext


def main():
  keys_pair = generate_keys()

  plaintext = 'rango brabo'
  ciphertext = crypt(plaintext, keys_pair['public'])
  deciphertext = crypt(ciphertext, keys_pair['private'])
  print(f'ciphertext: {ciphertext}')
  print(f'deciphertext: {deciphertext}')

main()