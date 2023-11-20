from random import randint

def genPrime() -> int:
  prime = 0
  notPrimes = []
  while not isPrime(prime):
    notPrimes.append(prime)
    while prime in notPrimes:
      prime = randint(1e6, 1e7-1)

  return prime

def isPrime(n: int) -> bool:
  # miller-rabin
  # https://www.youtube.com/watch?v=qdylJqXCDGs&ab_channel=Theoretically
  k = 0
  while isinstance((n - 1) / (2 ** k), int):
    k += 1
  m = (n - 1) / (2 ** k)
  a = randint(2, n - 2)

  a_, b = a, 0
  for _ in range(0, m - 1): # b = (a ** m) % n
    b = (a_ * a) % n

  return False

def gcd(a: int, b: int) -> int:
  if a == 0:
    return b
  return gcd(b % a, a)

def generate_key(p: int, q: int):
  n = p * q
  phi = (p - 1) * (q - 1)

  e = 0
  for i in range(2, phi):
    if gcd(i, phi) == 1:
      e = i
      break

  # d * e % phi == 1
  d = 0
  for i in range(2, phi):
    if (i * e) % phi == 1:
      d = i
      break

  d += phi * randint(1e4, 1e6)
  
  return { 'public': (e, n), 'private': (d, n) }

def encrypt():
  return

def decrypt():
  return


def main():
  res = generate_key(2, 7)
  print(res)
  return

main()