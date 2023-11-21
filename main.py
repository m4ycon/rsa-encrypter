from random import randint


def exp_mod(a: int, b: int, n: int) -> int:
  # (a ^ b) % n with fast exponentiation
  res = 1
  while b > 0:
    if b % 2 == 1:
      res = (res * a) % n
    a = (a * a) % n
    b = b // 2
  return res


def gen_prime() -> int:
  prime = randint(2e16, 2e17-1)
  not_primes = []
  while not is_prime(prime):
    not_primes.append(prime)

    while prime in not_primes:
      prime = randint(2e16, 2e17-1)

  return prime


def is_prime(n: int) -> bool:
  # miller-rabin
  # https://www.youtube.com/watch?v=qdylJqXCDGs&ab_channel=Theoretically
  k = 1
  while (n - 1) / (2 ** k) == int((n - 1) / (2 ** k)):
    k += 1
  k -= 1
  m = int((n - 1) / (2 ** k))
  a = randint(2, n - 2)

  b = exp_mod(a, m, n)
  return b == 1 or b == n - 1
  # TODO: check next bn's to confirm prime


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