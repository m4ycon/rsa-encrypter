from random import randint


def gen_prime() -> int:
  lower_bound, upper_bound = pow(2, 1024), pow(2, 1025) - 1
  prime = randint(lower_bound, upper_bound)
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


def gcd(a: int, b: int) -> int:
  if a == 0:
    return b
  return gcd(b % a, a)


def generate_key(p: int, q: int):
  # https://www.youtube.com/watch?v=oOcTVTpUsPQ&ab_channel=EddieWoo
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
  # res = generate_key(2, 7)
  prime = gen_prime()
  print(f'-> {prime}')

main()