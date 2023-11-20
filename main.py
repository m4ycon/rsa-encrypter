from random import randint

def gcd(a: int, b: int):
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